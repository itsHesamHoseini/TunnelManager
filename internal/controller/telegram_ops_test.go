package controller

import (
	"context"
	"github.com/itsHesamHoseini/TunnelManager/internal/secure"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestTelegramMutationsStayGatedUntilSingleUseConfirmation(t *testing.T) {
	s, _, _ := testServer(t)
	ctx := context.Background()
	s.settings.TelegramOperations = true
	id, e := s.newJob(ctx, "tg_gate", "tunnel-action", "synthetic", "Synthetic restart", JobPayload{AwaitTelegram: true})
	if e != nil {
		t.Fatal(e)
	}
	var phase string
	s.DB.QueryRow(ctx, "SELECT phase FROM operations WHERE id=$1", id).Scan(&phase)
	if phase != "awaiting_telegram" {
		t.Fatal("mutation queued before user approval")
	}
	token := secure.Token(24)
	s.DB.Exec(ctx, "INSERT INTO telegram_actions(hash,operation_id,expires)VALUES($1,$2,now()+interval '1 minute')", secure.Hash(token), id)
	if !s.telegramDecision(ctx, token, true) || s.telegramDecision(ctx, token, true) {
		t.Fatal("confirmation consumption not atomic")
	}
	s.DB.QueryRow(ctx, "SELECT phase FROM operations WHERE id=$1", id).Scan(&phase)
	if phase != "queued" {
		t.Fatal("approved action not queued")
	}
	expired, e := s.newJob(ctx, "tg_expired", "tunnel-action", "synthetic", "Expired restart", JobPayload{AwaitTelegram: true})
	if e != nil {
		t.Fatal(e)
	}
	token = secure.Token(24)
	s.DB.Exec(ctx, "INSERT INTO telegram_actions(hash,operation_id,expires)VALUES($1,$2,now()-interval '1 second')", secure.Hash(token), expired)
	if s.telegramDecision(ctx, token, true) {
		t.Fatal("expired action approved")
	}
}
func TestAlertNotificationsRespectSuppressionAndPersistCooldown(t *testing.T) {
	s, _, _ := testServer(t)
	ctx := context.Background()
	s.settings.TelegramAlerts = true
	s.settings.TelegramToken = "1:synthetic-fixture"
	s.settings.ChatID = "123456"
	old := telegramHTTP
	defer func() { telegramHTTP = old }()
	sent := 0
	telegramHTTP = &http.Client{Transport: fixtureTransport(func(r *http.Request) (*http.Response, error) {
		sent++
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"ok":true,"result":{}}`)), Header: make(http.Header)}, nil
	})}
	s.setAlert(ctx, "transport", "synthetic", "warning", "transport_check_failed", true)
	s.DB.Exec(ctx, "UPDATE alerts SET suppressed_until=now()+interval '1 hour'")
	s.notifyAlerts(ctx)
	if sent != 0 {
		t.Fatal("suppressed alert delivered")
	}
	s.DB.Exec(ctx, "UPDATE alerts SET suppressed_until=NULL")
	s.notifyAlerts(ctx)
	s.notifyAlerts(ctx)
	if sent != 1 {
		t.Fatal("alert cooldown not persisted")
	}
}
