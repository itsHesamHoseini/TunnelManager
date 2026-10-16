package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/itsHesamHoseini/TunnelManager/internal/secure"
	"strings"
	"time"
)

func (s *Server) telegramText(ctx context.Context, text string) {
	s.bot(ctx, "sendMessage", map[string]any{"chat_id": s.settingsCopy().ChatID, "text": short(text, 3900)})
}
func (s *Server) telegramCommand(ctx context.Context, update int64, message string) {
	st := s.settingsCopy()
	if !st.TelegramOperations || len(message) > 500 || s.Limiter.Allow("telegram-commands", .2, 3) > 0 {
		return
	}
	command, name, _ := strings.Cut(strings.TrimSpace(message), " ")
	name = strings.TrimSpace(name)
	if command == "/start" || command == "/help" {
		s.telegramText(ctx, "TunnelManager\n/status — وضعیت سرورها\n/tunnels — فهرست تونل‌ها\n/check نام تونل — بررسی محدود\n/restart نام تونل — درخواست ری‌استارت\n/stop نام تونل — درخواست توقف\n/start نام تونل — درخواست شروع\n/disable نام تونل — درخواست غیرفعال‌کردن\nتغییر فقط پس از دیدن اثر و تأیید دکمه انجام می‌شود.")
		return
	}
	if command == "/status" {
		rows, e := s.DB.Query(ctx, "SELECT name,seen FROM nodes WHERE approved ORDER BY name")
		if e != nil {
			return
		}
		lines := []string{"مشاهدهٔ عامل سرورها؛ سلامت تونل مستقل است:"}
		for rows.Next() {
			var name string
			var seen *time.Time
			rows.Scan(&name, &seen)
			status := "دادهٔ قدیمی یا مشاهده‌نشده"
			if seen != nil && time.Since(*seen) < 90*time.Second {
				status = "مشاهدهٔ تازه"
			}
			lines = append(lines, name+" — "+status)
		}
		rows.Close()
		s.telegramText(ctx, strings.Join(lines, "\n"))
		return
	}
	if command == "/tunnels" {
		rows, e := s.DB.Query(ctx, "SELECT name,desired,health FROM tunnels ORDER BY name LIMIT 50")
		if e != nil {
			return
		}
		lines := []string{"تونل‌ها — نتیجهٔ TCP با سلامت کامل مسیر برابر نیست:"}
		for rows.Next() {
			var name, desired string
			var raw []byte
			rows.Scan(&name, &desired, &raw)
			var h struct {
				At        time.Time `json:"at"`
				Transport struct {
					Status string `json:"status"`
				} `json:"transport"`
			}
			json.Unmarshal(raw, &h)
			status := "نامعلوم"
			if time.Since(h.At) < 3*time.Minute {
				if h.Transport.Status == "passed" {
					status = "TCP موفق"
				} else if h.Transport.Status == "failed" {
					status = "TCP ناموفق"
				}
			}
			if desired != "running" {
				status = "توقف عمدی"
			}
			lines = append(lines, name+" — "+status)
		}
		rows.Close()
		s.telegramText(ctx, strings.Join(lines, "\n"))
		return
	}
	if name == "" {
		s.telegramText(ctx, "نام کامل تونل را پس از دستور بنویسید؛ /tunnels")
		return
	}
	rows, e := s.DB.Query(ctx, "SELECT id,name FROM tunnels WHERE lower(name)=lower($1) LIMIT 2", name)
	if e != nil {
		return
	}
	ids := []string{}
	friendly := ""
	for rows.Next() {
		var id string
		rows.Scan(&id, &friendly)
		ids = append(ids, id)
	}
	rows.Close()
	if len(ids) != 1 {
		s.telegramText(ctx, "نام پیدا نشد یا تکراری است؛ نام کامل و یکتای تونل را از پنل انتخاب کنید.")
		return
	}
	target := ids[0]
	record, revision, managed, e := s.readTunnel(ctx, target)
	if e != nil {
		return
	}
	requestKey := fmt.Sprintf("telegram_%d", update)
	if command == "/check" {
		id, e := s.newJob(ctx, requestKey, "tunnel-check", target, friendly, JobPayload{Tunnel: target, TelegramReply: true})
		if e == nil {
			s.telegramText(ctx, "بررسی محدود برای «"+friendly+"» ثبت شد؛ نتیجه ارسال می‌شود. "+id[:6])
		}
		return
	}
	action := strings.TrimPrefix(command, "/")
	if !strings.Contains("|start|stop|restart|disable|", "|"+action+"|") {
		s.telegramText(ctx, "دستور شناخته نشد؛ /help")
		return
	}
	if !managed {
		s.telegramText(ctx, "ابتدا پذیرش مدیریت این سرویس‌های موجود را در پنل تأیید کنید.")
		return
	}
	payload := JobPayload{Tunnel: target, Name: friendly, Spec: record.Spec, Instances: record.Instances, Hashes: record.Hashes, ExpectedRevision: revision, Action: action, Confirm: true, AwaitTelegram: true, TelegramReply: true}
	if e = s.expand(ctx, &payload); e != nil {
		s.telegramText(ctx, "اثر سرویس مشترک نیازمند بررسی است؛ عملیات را از صفحهٔ تونل در پنل بازبینی کنید.")
		return
	}
	id, e := s.newJob(ctx, requestKey, "tunnel-action", target, friendly, payload)
	if e != nil {
		return
	}
	var phase string
	s.DB.QueryRow(ctx, "SELECT phase FROM operations WHERE id=$1", id).Scan(&phase)
	if phase != "awaiting_telegram" {
		return
	}
	s.DB.Exec(ctx, "UPDATE operations SET deadline=now()+interval '2 minutes' WHERE id=$1", id)
	token := secure.Token(24)
	_, e = s.DB.Exec(ctx, "INSERT INTO telegram_actions(hash,operation_id,expires)VALUES($1,$2,now()+interval '2 minutes')", secure.Hash(token), id)
	if e != nil {
		return
	}
	routes := []string{}
	for _, g := range payload.Updates {
		for _, r := range g.Record.Spec.Routes {
			routes = append(routes, g.Name+" / "+r.Name)
		}
	}
	text := "درخواست «" + action + "» برای «" + friendly + "»\nمسیرهای سرویس‌های تحت تأثیر: " + strings.Join(routes, "، ") + "\nممکن است ارتباط این مسیرها قطع شود. توقف عمدی در بازیابی حفظ می‌شود.\nاین تأیید فقط دو دقیقه و یک‌بار معتبر است."
	_, e = s.bot(ctx, "sendMessage", map[string]any{"chat_id": st.ChatID, "text": text, "reply_markup": map[string]any{"inline_keyboard": [][]map[string]string{{{"text": "تأیید و اجرا", "callback_data": "opok:" + token}, {"text": "انصراف", "callback_data": "opno:" + token}}}}})
	if e != nil {
		s.phase(ctx, id, "failed", nil, errors.New("telegram_confirmation_delivery_failed"))
	}
	s.Audit(ctx, "telegram-operation-request", friendly, "awaiting-explicit-confirmation")
}
func (s *Server) telegramDecision(ctx context.Context, token string, approve bool) bool {
	phase := "cancelled"
	if approve {
		phase = "queued"
	}
	tag, e := s.DB.Exec(ctx, `WITH chosen AS(UPDATE telegram_actions SET consumed=true WHERE hash=$1 AND expires>now() AND NOT consumed RETURNING operation_id)UPDATE operations SET phase=$2,updated=now() WHERE id IN(SELECT operation_id FROM chosen) AND phase='awaiting_telegram'`, secure.Hash(token), phase)
	if e == nil && tag.RowsAffected() == 1 {
		s.Audit(ctx, "telegram-operation-confirmation", "", phase)
		return true
	}
	return false
}
func (s *Server) notifyOperation(ctx context.Context, id string, q JobPayload) {
	if !q.TelegramReply || !s.settingsCopy().TelegramOperations {
		return
	}
	var phase, code, name string
	if s.DB.QueryRow(ctx, "SELECT phase,error,name FROM operations WHERE id=$1", id).Scan(&phase, &code, &name) != nil {
		return
	}
	if phase == "succeeded" {
		s.telegramText(ctx, "عملیات «"+name+"» انجام شد؛ مشاهدهٔ جزئیات: پنل ← عملیات")
	} else if phase == "failed" {
		s.telegramText(ctx, "عملیات «"+name+"» ناموفق بود.\nکد: "+short(code, 100)+"\nاقدام بعدی: نتیجهٔ هر سرور را در پنل ← عملیات بررسی کنید.")
	}
}
func (s *Server) notifyAlerts(ctx context.Context) {
	st := s.settingsCopy()
	if !st.TelegramAlerts {
		return
	}
	repeat := st.AlertRepeatMinutes
	if repeat == 0 {
		repeat = 60
	}
	rows, e := s.DB.Query(ctx, `SELECT a.id,COALESCE(n.name,t.name,c.name,a.target),a.code FROM alerts a LEFT JOIN nodes n ON n.id=a.target LEFT JOIN tunnels t ON t.id=a.target LEFT JOIN certificates c ON c.id=a.target WHERE a.active AND NOT a.acknowledged AND(a.suppressed_until IS NULL OR a.suppressed_until<now())AND(a.notified IS NULL OR a.notified<now()-$1*interval '1 minute')AND(a.notification_attempt IS NULL OR a.notification_attempt<now()-interval '5 minutes')ORDER BY a.created LIMIT 3`, repeat)
	if e != nil {
		return
	}
	type item struct {
		id         int64
		name, code string
	}
	items := []item{}
	for rows.Next() {
		var v item
		rows.Scan(&v.id, &v.name, &v.code)
		items = append(items, v)
	}
	rows.Close()
	for _, v := range items {
		s.DB.Exec(ctx, "UPDATE alerts SET notification_attempt=now() WHERE id=$1", v.id)
		_, e := s.bot(ctx, "sendMessage", map[string]any{"chat_id": st.ChatID, "text": "هشدار TunnelManager\n" + v.name + "\n" + v.code + "\nاقدام بعدی: پنل ← هشدارها / بررسی مسیر"})
		if e == nil {
			s.DB.Exec(ctx, "UPDATE alerts SET notified=now() WHERE id=$1", v.id)
		}
	}
}
