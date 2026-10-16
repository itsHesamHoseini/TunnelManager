package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/itsHesamHoseini/TunnelManager/internal/secure"
	"io"
	"net/http"
	"strings"
	"time"
)

var telegramHTTP = &http.Client{Timeout: 12 * time.Second}

func (s *Server) bot(ctx context.Context, method string, payload any) (json.RawMessage, error) {
	st := s.settingsCopy()
	if st.TelegramToken == "" {
		return nil, errors.New("bot not configured")
	}
	if !strings.Contains(st.TelegramToken, ":") || strings.ContainsAny(st.TelegramToken, "/\n\r?#") {
		return nil, errors.New("invalid bot token")
	}
	body, _ := json.Marshal(payload)
	req, e := http.NewRequestWithContext(ctx, "POST", "https://api.telegram.org/bot"+st.TelegramToken+"/"+method, bytes.NewReader(body))
	if e != nil {
		return nil, errors.New("messaging unavailable")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, e := telegramHTTP.Do(req)
	if e != nil {
		return nil, errors.New("messaging unavailable")
	}
	defer resp.Body.Close()
	b, e := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if e != nil || resp.StatusCode != 200 {
		return nil, errors.New("messaging unavailable")
	}
	var v struct {
		OK     bool            `json:"ok"`
		Result json.RawMessage `json:"result"`
	}
	if json.Unmarshal(b, &v) != nil || !v.OK {
		return nil, errors.New("messaging request rejected")
	}
	return v.Result, nil
}
func (s *Server) telegramTest(w http.ResponseWriter, r *http.Request) {
	if s.limited(w, r, "telegram-test", .016, 1) {
		return
	}
	_, e := s.bot(r.Context(), "sendMessage", map[string]any{"chat_id": s.settingsCopy().ChatID, "text": "TunnelManager: test message. Confirm receipt in the panel."})
	if e != nil {
		fail(w, 502, "telegram_unavailable", "Check the bot token, chat ID and network.", "توکن ربات، شناسهٔ گفتگو و ارتباط شبکه را بررسی کنید.")
		return
	}
	write(w, map[string]bool{"sent": true})
}
func (s *Server) telegramRequest(w http.ResponseWriter, r *http.Request) {
	if s.limited(w, r, "telegram-login", .016, 1) {
		return
	}
	st := s.settingsCopy()
	if !st.TelegramEnabled {
		fail(w, 400, "disabled", "Use your authenticator.", "از برنامهٔ تأیید هویت استفاده کنید.")
		return
	}
	var yes bool
	e := s.DB.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM challenges WHERE hash=$1 AND kind='mfa' AND expires>now())", challenge(r)).Scan(&yes)
	if e != nil || !yes {
		fail(w, 401, "challenge_expired", "Sign in again.", "دوباره وارد شوید.")
		return
	}
	c, _ := r.Cookie("tm_challenge")
	_, e = s.bot(r.Context(), "sendMessage", map[string]any{"chat_id": st.ChatID, "text": fmt.Sprintf("TunnelManager login\nIP: %s\nTime: %s\nBrowser: %s\nExpires in 2 minutes.", s.ip(r), time.Now().UTC().Format(time.RFC3339), short(r.UserAgent(), 150)), "reply_markup": map[string]any{"inline_keyboard": [][]map[string]string{{{"text": "Approve", "callback_data": "ok:" + c.Value}, {"text": "Deny", "callback_data": "no:" + c.Value}}}}})
	if e != nil {
		fail(w, 502, "telegram_unavailable", "Telegram unavailable. Use TOTP or a recovery code.", "تلگرام در دسترس نیست؛ از کد برنامه یا کد بازیابی استفاده کنید.")
		return
	}
	write(w, map[string]bool{"sent": true})
}
func (s *Server) TelegramLoop(ctx context.Context) {
	offset := int64(0)
	s.DB.QueryRow(ctx, "SELECT offset_value FROM telegram_cursor WHERE id=1").Scan(&offset)
	tick := time.NewTicker(3 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		st := s.settingsCopy()
		if !st.TelegramEnabled && !st.TelegramAlerts && !st.TelegramOperations {
			continue
		}
		s.notifySecurity(ctx)
		s.notifyAlerts(ctx)
		b, e := s.bot(ctx, "getUpdates", map[string]any{"offset": offset, "timeout": 0, "allowed_updates": []string{"callback_query", "message"}, "limit": 20})
		if e != nil {
			continue
		}
		var updates []struct {
			ID      int64 `json:"update_id"`
			Message struct {
				Text string `json:"text"`
				From struct {
					ID int64 `json:"id"`
				} `json:"from"`
				Chat struct {
					ID int64 `json:"id"`
				} `json:"chat"`
			} `json:"message"`
			Callback struct {
				ID   string `json:"id"`
				Data string `json:"data"`
				From struct {
					ID int64 `json:"id"`
				} `json:"from"`
				Message struct {
					Chat struct {
						ID int64 `json:"id"`
					} `json:"chat"`
				} `json:"message"`
			} `json:"callback_query"`
		}
		if json.Unmarshal(b, &updates) != nil {
			continue
		}
		for _, u := range updates {
			if u.ID >= offset {
				offset = u.ID + 1
			}
			if u.Message.Text != "" && fmt.Sprint(u.Message.Chat.ID) == st.ChatID && fmt.Sprint(u.Message.From.ID) == st.ChatID {
				s.telegramCommand(ctx, u.ID, u.Message.Text)
			}
			q := u.Callback
			if fmt.Sprint(q.From.ID) != st.ChatID || fmt.Sprint(q.Message.Chat.ID) != st.ChatID {
				continue
			}
			bits := strings.SplitN(q.Data, ":", 2)
			if len(bits) != 2 {
				continue
			}
			result := "Expired or already used"
			if bits[0] == "opok" || bits[0] == "opno" {
				if st.TelegramOperations && s.telegramDecision(ctx, bits[1], bits[0] == "opok") {
					result = "درخواست ثبت شد؛ نتیجه در همین گفتگو ارسال می‌شود."
				}
			} else if bits[0] == "ok" {
				tag, e := s.DB.Exec(ctx, "UPDATE challenges SET approved=true WHERE hash=$1 AND kind='mfa' AND expires>now() AND NOT approved", secure.Hash(bits[1]))
				if e == nil && tag.RowsAffected() == 1 {
					result = "Approved. Return to the panel."
					s.Audit(ctx, "telegram-approval", "", "approved")
				}
			} else if bits[0] == "no" {
				s.DB.Exec(ctx, "DELETE FROM challenges WHERE hash=$1", secure.Hash(bits[1]))
				result = "Denied"
			}
			s.bot(ctx, "answerCallbackQuery", map[string]string{"callback_query_id": q.ID, "text": result})
		}
		s.DB.Exec(ctx, "INSERT INTO telegram_cursor(id,offset_value)VALUES(1,$1)ON CONFLICT(id)DO UPDATE SET offset_value=GREATEST(telegram_cursor.offset_value,EXCLUDED.offset_value)", offset)
	}
}

// One bounded notification per five minutes; persisted audit timestamps prevent
// resending old violations after a controller restart. No credentials in messages.
func (s *Server) notifySecurity(ctx context.Context) {
	st := s.settingsCopy()
	if !st.TelegramEnabled || st.TelegramToken == "" {
		return
	}
	var repeated bool
	if s.DB.QueryRow(ctx, `SELECT count(*)>=2 OR COALESCE(bool_or(action='auth-lockout'),false) FROM audit WHERE action IN ('rate-limit','auth-lockout') AND at>now()-interval '15 minutes' AND at>COALESCE((SELECT max(at) FROM audit WHERE action='security-notification'),'-infinity'::timestamptz)`).Scan(&repeated) != nil || !repeated {
		return
	}
	if s.Limiter.Allow("security-notification", 1.0/300, 1) > 0 {
		return
	}
	_, e := s.bot(ctx, "sendMessage", map[string]any{"chat_id": st.ChatID, "text": "TunnelManager: repeated access limits detected. Review Security → Audit. / درخواست‌های مکرر محدود شدند؛ بخش امنیت و ثبت عملیات را بررسی کنید."})
	if e == nil {
		s.Audit(ctx, "security-notification", "", "sent")
	}
}
