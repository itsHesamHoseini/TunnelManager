package controller

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type fixtureTransport func(*http.Request) (*http.Response, error)

func (f fixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestTelegramFixedEndpointAndExpiredChallenge(t *testing.T) {
	s, srv, c := testServer(t)
	s.settings.TelegramToken = "1:synthetic-fixture"
	s.settings.ChatID = "123456"
	s.settings.TelegramEnabled = true
	old := telegramHTTP
	defer func() { telegramHTTP = old }()
	called := 0
	telegramHTTP = &http.Client{Transport: fixtureTransport(func(r *http.Request) (*http.Response, error) {
		called++
		if r.URL.Scheme != "https" || r.URL.Host != "api.telegram.org" || !strings.HasSuffix(r.URL.Path, "/sendMessage") {
			t.Fatal("unexpected provider endpoint")
		}
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "123456") {
			t.Fatal("wrong chat")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("{\"ok\":true,\"result\":{\"message_id\":1}}")), Header: make(http.Header)}, nil
	})}
	if _, e := s.bot(context.Background(), "sendMessage", map[string]string{"chat_id": "123456", "text": "Synthetic verification"}); e != nil {
		t.Fatal(e)
	}
	status, _ := request(t, c, srv.URL+"/api/mfa/telegram", "POST", nil)
	if status != 401 || called != 1 {
		t.Fatal("expired challenge sent approval")
	}
}

func TestSecurityNotificationCooldownAndRestart(t *testing.T) {
	s, _, _ := testServer(t)
	s.settings.TelegramToken = "1:synthetic-fixture"
	s.settings.ChatID = "123456"
	s.settings.TelegramEnabled = true
	old := telegramHTTP
	defer func() { telegramHTTP = old }()
	called := 0
	telegramHTTP = &http.Client{Transport: fixtureTransport(func(r *http.Request) (*http.Response, error) {
		called++
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"ok":true,"result":{}}`)), Header: make(http.Header)}, nil
	})}
	ctx := context.Background()
	s.Audit(ctx, "rate-limit", "", "throttled")
	s.Audit(ctx, "rate-limit", "", "throttled")
	s.notifySecurity(ctx)
	s.notifySecurity(ctx)
	if called != 1 {
		t.Fatal("security notice duplicated", called)
	}
	// New violations remain bounded, even if polling repeats immediately.
	s.Audit(ctx, "rate-limit", "", "throttled")
	s.Audit(ctx, "rate-limit", "", "throttled")
	s.notifySecurity(ctx)
	if called != 1 {
		t.Fatal("notification cooldown bypassed")
	}
}
