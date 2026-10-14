package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/itsHesamHoseini/TunnelManager/internal/config"
	"github.com/skip2/go-qrcode"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"time"
)

func terminalOnboarding(ctx context.Context, c config.Config, password string) error {
	choice, e := ask("Enroll TOTP now in this terminal? (yes/no)", "yes")
	if e != nil {
		return e
	}
	if choice != "yes" {
		fmt.Println("First web login will require TOTP enrollment.")
		return nil
	}
	roots, _ := x509.SystemCertPool()
	if roots == nil {
		roots = x509.NewCertPool()
	}
	if c.TLS != "proxy" {
		pem, e := os.ReadFile(filepath.Join(c.ConfigDir, "tls/cert.pem"))
		if e != nil {
			return e
		}
		roots.AppendCertsFromPEM(pem)
	}
	jar, _ := cookiejar.New(nil)
	client := http.Client{Timeout: 15 * time.Second, Jar: jar, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}}, CheckRedirect: func(r *http.Request, via []*http.Request) error { return errors.New("redirect refused") }}
	call := func(path, method string, payload any) (map[string]any, error) {
		b, _ := json.Marshal(payload)
		r, e := http.NewRequestWithContext(ctx, method, c.Origin()+"/api/"+path, bytes.NewReader(b))
		if e != nil {
			return nil, e
		}
		r.Header.Set("Content-Type", "application/json")
		resp, e := client.Do(r)
		if e != nil {
			return nil, errors.New("secure onboarding unavailable; use the web panel")
		}
		defer resp.Body.Close()
		var data map[string]any
		if json.NewDecoder(io.LimitReader(resp.Body, 65536)).Decode(&data) != nil || resp.StatusCode != 200 {
			return nil, errors.New("onboarding request failed; continue in the web panel")
		}
		return data, nil
	}
	v, e := call("login", "POST", map[string]string{"Username": c.Admin, "Password": password})
	if e != nil {
		return e
	}
	if v["next"] != "enroll" {
		fmt.Println("TOTP already configured; preserved.")
		return nil
	}
	v, e = call("mfa/enroll", "GET", nil)
	if e != nil {
		return e
	}
	uri, _ := v["uri"].(string)
	qr, e := qrcode.New(uri, qrcode.Medium)
	if e != nil {
		return e
	}
	fmt.Println("Scan with your authenticator. This QR is private and shown only here.")
	fmt.Print(qr.ToSmallString(false))
	code, e := secret("Six-digit authenticator code")
	if e != nil {
		return e
	}
	v, e = call("mfa/enroll", "POST", map[string]string{"Code": code})
	if e != nil {
		return e
	}
	fmt.Println("Recovery codes (shown once; store privately):")
	if codes, ok := v["recovery_codes"].([]any); ok {
		for _, code := range codes {
			fmt.Println(code)
		}
	}
	choice, e = ask("Configure optional Telegram approval now? (yes/no)", "no")
	if e != nil || choice != "yes" {
		return e
	}
	token, e := secret("Telegram bot token")
	if e != nil {
		return e
	}
	chat, e := secret("Private chat ID")
	if e != nil {
		return e
	}
	_, e = call("settings", "PUT", map[string]any{"language": c.Language, "profile": c.Profile, "telegram_token": token, "chat_id": chat, "telegram_enabled": true})
	if e != nil {
		return e
	}
	_, e = call("settings/telegram-test", "POST", map[string]any{})
	if e != nil {
		return e
	}
	choice, e = ask("Did you receive the test message? (yes/no)", "no")
	if e != nil {
		return e
	}
	if choice != "yes" {
		_, e = call("settings", "PUT", map[string]any{"language": c.Language, "profile": c.Profile, "chat_id": chat, "telegram_enabled": false})
		fmt.Println("Telegram approval disabled; TOTP/recovery remains available.")
	}
	return e
}
