package nodeops

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/itsHesamHoseini/TunnelManager/internal/engine"
)

var secretLog = regexp.MustCompile(`(?i)(token|password|secret|authorization|private_key|uuid)\s*[:=]\s*[^\s,;]+`)
var credentialsURL = regexp.MustCompile(`(?i)(vless|vmess|trojan|ss|https?)://[^\s]+`)
var uuidRE = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
var pemLog = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)`)

func redactLog(s string) string {
	s = pemLog.ReplaceAllString(s, "[redacted private material]")
	s = secretLog.ReplaceAllString(s, "$1="+engine.Mask)
	s = credentialsURL.ReplaceAllString(s, "[redacted URI]")
	return uuidRE.ReplaceAllString(s, engine.Mask)
}
func (r *Runtime) logs(ctx context.Context, b []byte) (any, error) {
	var q struct {
		ID, Search, Severity, Since string
		Limit                       int
	}
	if e := decode(b, &q); e != nil {
		return nil, e
	}
	v, e := r.resolve(ctx, q.ID)
	if e != nil {
		return nil, e
	}
	if q.Limit < 1 || q.Limit > 300 {
		q.Limit = 100
	}
	since := time.Now().Add(-time.Hour)
	if q.Since != "" {
		t, e := time.Parse(time.RFC3339, q.Since)
		if e != nil || t.Before(time.Now().Add(-7*24*time.Hour)) || t.After(time.Now()) {
			return nil, errors.New("invalid_log_time_range")
		}
		since = t
	}
	out, e := run(ctx, "journalctl", "-u", v.Unit, "--no-pager", "-o", "json", "-n", fmt.Sprint(q.Limit), "--since", since.UTC().Format(time.RFC3339))
	if e != nil {
		return nil, e
	}
	lines := []map[string]any{}
	var secrets []string
	if raw, e := readRegular(v.Path, 65536); e == nil {
		secrets = rawSecrets(string(raw))
	}
	scan := bufio.NewScanner(bytes.NewReader(out))
	scan.Buffer(make([]byte, 4096), 65536)
	for scan.Scan() {
		var row map[string]any
		if json.Unmarshal(scan.Bytes(), &row) != nil {
			continue
		}
		message, _ := row["MESSAGE"].(string)
		if len(message) > 4000 {
			message = message[:4000]
		}
		message = redactLog(message)
		for _, secret := range secrets {
			message = strings.ReplaceAll(message, secret, engine.Mask)
		}
		if q.Search != "" && !strings.Contains(strings.ToLower(message), strings.ToLower(q.Search)) {
			continue
		}
		priority, _ := row["PRIORITY"].(string)
		if q.Severity == "error" && priority > "3" {
			continue
		}
		cause := ""
		lower := strings.ToLower(message)
		switch {
		case strings.Contains(lower, "connection refused"):
			cause = "probable_backend_not_listening"
		case strings.Contains(lower, "certificate"):
			cause = "probable_certificate_or_clock"
		case strings.Contains(lower, "address already in use"):
			cause = "probable_port_conflict"
		case strings.Contains(lower, "timeout"):
			cause = "probable_network_or_firewall"
		}
		lines = append(lines, map[string]any{"message": message, "priority": priority, "at_microseconds": row["__REALTIME_TIMESTAMP"], "probable_cause": cause})
	}
	return map[string]any{"lines": lines, "scope": "selected systemd unit; secrets redacted; up to 300 journal entries"}, nil
}

type Diagnostic struct {
	Kind       string          `json:"kind"`
	Endpoint   engine.Endpoint `json:"endpoint"`
	ServerName string          `json:"server_name"`
	CA         string          `json:"ca"`
	Path       string          `json:"path"`
	Expected   string          `json:"expected"`
	Bytes      int             `json:"bytes"`
	Confirm    bool            `json:"confirm"`
}

func (r *Runtime) diagnostic(ctx context.Context, b []byte) (any, error) {
	var q Diagnostic
	if e := decode(b, &q); e != nil {
		return nil, e
	}
	if !engine.ValidHost(q.Endpoint.Host) || q.Endpoint.Port < 1 || q.Endpoint.Port > 65535 {
		return nil, errors.New("invalid_diagnostic_target")
	}
	if ip := net.ParseIP(q.Endpoint.Host); ip != nil && (ip.IsMulticast() || ip.IsUnspecified() || ip.IsLinkLocalUnicast()) {
		return nil, errors.New("diagnostic_target_not_allowed")
	}
	start := time.Now()
	out := map[string]any{"kind": q.Kind, "target": q.Endpoint.String(), "at": start.UTC(), "scope": "single source node; no configuration changes", "status": "failed"}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	var err error
	switch q.Kind {
	case "ping":
		if strings.HasPrefix(q.Endpoint.Host, "-") {
			return nil, errors.New("invalid_ping_target")
		}
		v, e := run(ctx, "ping", "-n", "-c", "3", "-W", "1", q.Endpoint.Host)
		err = e
		if e == nil {
			out["detail"] = redactLog(string(v))
			out["packets"] = 3
		}
	case "tcp":
		var conn net.Conn
		conn, err = (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", q.Endpoint.String())
		if conn != nil {
			conn.Close()
		}
	case "tls":
		cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: q.ServerName}
		if cfg.ServerName == "" {
			cfg.ServerName = q.Endpoint.Host
		}
		if q.CA != "" {
			if !engine.ID(q.CA) {
				return nil, errors.New("invalid_certificate_reference")
			}
			pem, e := os.ReadFile(filepath.Join(r.ConfigDir, "certificates", q.CA, "cert.pem"))
			if e != nil {
				return nil, errors.New("trusted_certificate_missing")
			}
			pool, _ := x509.SystemCertPool()
			if pool == nil {
				pool = x509.NewCertPool()
			}
			pool.AppendCertsFromPEM(pem)
			cfg.RootCAs = pool
		}
		var rawConn net.Conn
		rawConn, err = (&tls.Dialer{NetDialer: &net.Dialer{Timeout: 3 * time.Second}, Config: cfg}).DialContext(ctx, "tcp", q.Endpoint.String())
		conn, _ := rawConn.(*tls.Conn)
		if conn != nil {
			out["tls_version"] = conn.ConnectionState().Version
			out["verified"] = len(conn.ConnectionState().VerifiedChains) > 0
			conn.Close()
		}
	case "http":
		if q.Path == "" {
			q.Path = "/"
		}
		if !strings.HasPrefix(q.Path, "/") || strings.ContainsAny(q.Path, "\r\n") || len(q.Path) > 500 {
			return nil, errors.New("invalid_application_path")
		}
		client := http.Client{Timeout: 4 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		req, _ := http.NewRequestWithContext(ctx, "GET", "http://"+q.Endpoint.String()+q.Path, nil)
		var res *http.Response
		res, err = client.Do(req)
		if err == nil {
			defer client.CloseIdleConnections()
			body, e := io.ReadAll(io.LimitReader(res.Body, 4097))
			res.Body.Close()
			out["http_status"] = res.StatusCode
			out["received_bytes"] = len(body)
			if e != nil || res.StatusCode < 200 || res.StatusCode >= 400 || (q.Expected != "" && !bytes.Contains(body, []byte(q.Expected))) {
				err = errors.New("application_response_mismatch")
			}
		}
	case "echo", "speed":
		if q.Kind == "speed" && !q.Confirm {
			return nil, errors.New("explicit_speed_test_confirmation_required")
		}
		n := 128
		if q.Kind == "speed" {
			n = q.Bytes
			if n < 1024 || n > 65536 {
				n = 32768
			}
		}
		data := make([]byte, n)
		rand.Read(data)
		var conn net.Conn
		conn, err = (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", q.Endpoint.String())
		if err == nil {
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(4 * time.Second))
			_, err = conn.Write(data)
			if err == nil {
				got := make([]byte, n)
				_, err = io.ReadFull(conn, got)
				if err == nil && !bytes.Equal(got, data) {
					err = errors.New("echo_response_mismatch")
				}
			}
			if err == nil {
				out["bytes"] = n
				out["observed_bytes_per_second"] = float64(n) / time.Since(start).Seconds()
				out["scope"] = "one bounded echo sample, not link capacity"
			}
		}
	default:
		return nil, errors.New("unsupported_diagnostic_kind")
	}
	out["duration_ms"] = time.Since(start).Milliseconds()
	if err == nil {
		out["status"] = "passed"
	} else {
		out["code"] = "connection_or_protocol_check_failed"
	}
	return out, nil
}
