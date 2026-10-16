package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/coder/websocket"
	"github.com/itsHesamHoseini/TunnelManager/internal/config"
	"github.com/itsHesamHoseini/TunnelManager/internal/nodeops"
	"github.com/itsHesamHoseini/TunnelManager/internal/protocol"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func Client(c config.Config) (*http.Client, error) {
	pool, e := x509.SystemCertPool()
	if e != nil {
		pool = x509.NewCertPool()
	}
	if c.CA != "" {
		b, e := os.ReadFile(c.CA)
		if e != nil || !pool.AppendCertsFromPEM(b) {
			return nil, errors.New("explicit controller CA invalid")
		}
	}
	return &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}, CheckRedirect: func(r *http.Request, via []*http.Request) error { return errors.New("controller redirects refused") }}, nil
}
func Enroll(ctx context.Context, c config.Config, token string) (config.Config, error) {
	c.Controller = strings.TrimRight(c.Controller, "/")
	u, e := url.Parse(c.Controller)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return c, errors.New("controller must be an HTTPS origin")
	}
	if len(token) < 20 || len(token) > 128 {
		return c, errors.New("one-time enrollment token invalid")
	}
	os.MkdirAll(c.ConfigDir, 0700)
	c.Identity = filepath.Join(c.ConfigDir, "identity.key")
	var key ed25519.PrivateKey
	if b, e := os.ReadFile(c.Identity); e == nil {
		if len(b) != ed25519.PrivateKeySize {
			return c, errors.New("identity file invalid")
		}
		key = b
	} else {
		_, key, e = ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return c, e
		}
		if e = config.Atomic(c.Identity, key, 0600); e != nil {
			return c, e
		}
	}
	client, e := Client(c)
	if e != nil {
		return c, e
	}
	body, _ := json.Marshal(map[string]string{"token": token, "public_key": base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))})
	r, e := http.NewRequestWithContext(ctx, "POST", u.String()+"/api/enroll", bytes.NewReader(body))
	if e != nil {
		return c, e
	}
	r.Header.Set("Content-Type", "application/json")
	resp, e := client.Do(r)
	if e != nil {
		return c, errors.New("secure enrollment connection failed; check domain and CA trust")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return c, errors.New("enrollment rejected; token expired/used or rate limited")
	}
	var v struct {
		NodeID string `json:"node_id"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 65536)).Decode(&v) != nil || v.NodeID == "" {
		return c, errors.New("enrollment response invalid")
	}
	c.NodeID = v.NodeID
	return c, config.Write(filepath.Join(c.ConfigDir, "node.json"), c)
}
func Run(ctx context.Context, c config.Config) error {
	b, e := os.ReadFile(c.Identity)
	if e != nil || len(b) != 64 {
		return errors.New("node identity unavailable")
	}
	st, e := os.Stat(c.Identity)
	if e != nil || st.Mode().Perm()&0077 != 0 {
		return errors.New("node identity must have mode 600")
	}
	key := ed25519.PrivateKey(b)
	client, e := Client(c)
	if e != nil {
		return e
	}
	sampler := NewSampler()
	ops := nodeops.New(c)
	var latest protocol.Telemetry
	var sampleMu sync.RWMutex
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			data := sampler.Collect(ctx)
			sampleMu.Lock()
			latest = data
			sampleMu.Unlock()
			observationCtx, done := context.WithTimeout(ctx, 8*time.Second)
			ops.Observe(observationCtx, data)
			done()
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	sample := func() protocol.Telemetry { sampleMu.RLock(); defer sampleMu.RUnlock(); return latest }
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return nil
		}
		saveStatus("connecting", time.Time{})
		e = connection(ctx, c, key, client, ops, sample)
		if e != nil {
			saveStatus("disconnected_or_pending_approval", time.Time{})
		}
		if ctx.Err() != nil {
			return nil
		}
		if e == nil {
			backoff = time.Second
		} else {
			backoff *= 2
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
	}
}
func connection(ctx context.Context, c config.Config, key ed25519.PrivateKey, client *http.Client, ops *nodeops.Runtime, sample func() protocol.Telemetry) error {
	u, e := url.Parse(c.Controller)
	if e != nil || u.Scheme != "https" {
		return errors.New("HTTPS controller required")
	}
	u.Scheme = "wss"
	u.Path = "/api/agent"
	conn, _, e := websocket.Dial(ctx, u.String(), &websocket.DialOptions{HTTPClient: client})
	if e != nil {
		return errors.New("controller connection unavailable")
	}
	defer conn.CloseNow()
	conn.SetReadLimit(protocol.MaxFrame)
	authCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_, b, e := conn.Read(authCtx)
	if e != nil {
		return e
	}
	var h protocol.Hello
	if json.Unmarshal(b, &h) != nil || h.Nonce == "" || h.Expires.Before(time.Now()) || h.Expires.After(time.Now().Add(30*time.Second)) {
		return errors.New("controller challenge invalid")
	}
	message := c.NodeID + "\n" + h.Nonce + "\n" + h.Expires.UTC().Format(time.RFC3339Nano)
	auth := protocol.Authentication{Protocol: 2, NodeID: c.NodeID, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(message)))}
	b, _ = json.Marshal(auth)
	if e = conn.Write(authCtx, websocket.MessageText, b); e != nil {
		return e
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	nextSample := time.Time{}
	pending := []protocol.Result{}
	for {
		frame := protocol.Frame{Type: "poll", Version: 2, Results: pending}
		data := sample()
		if !data.At.IsZero() && data.At.After(nextSample) {
			frame.Type = "telemetry"
			frame.Data = &data
			nextSample = data.At
		}

		b, e = json.Marshal(frame)
		if e != nil || len(b) > protocol.MaxFrame {
			return errors.New("measurement/result exceeds safe protocol frame")
		}
		sendCtx, done := context.WithTimeout(ctx, 12*time.Second)
		e = conn.Write(sendCtx, websocket.MessageText, b)
		if e == nil {
			_, b, e = conn.Read(sendCtx)
		}
		done()
		if e != nil {
			return e
		}
		var ack protocol.Ack
		if json.Unmarshal(b, &ack) != nil || ack.Type != "accepted" {
			return errors.New("unknown controller message rejected")
		}
		pending = nil
		saveStatus("connected", time.Now())
		if ack.Command != nil {
			pending = append(pending, ops.Execute(ctx, *ack.Command))
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
