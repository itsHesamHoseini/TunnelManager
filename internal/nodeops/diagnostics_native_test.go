//go:build linux && nativelab

package nodeops

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/itsHesamHoseini/TunnelManager/internal/engine"
	"github.com/itsHesamHoseini/TunnelManager/internal/protocol"
)

// Actual Linux sockets, OS ping and durable receipts; all targets are loopback
// fixtures on a disposable runner. No engine, server or public target is changed.
func TestNativeBoundedDiagnostics(t *testing.T) {
	if os.Getenv("CI") != "true" || os.Getenv("TUNNELMANAGER_NATIVE_LAB") != "1" {
		t.Skip("disposable Linux CI only")
	}
	r := &Runtime{StateDir: t.TempDir(), ConfigDir: t.TempDir()}
	var requests atomic.Int64
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		requests.Add(1)
		if q.URL.Path == "/bad" {
			w.WriteHeader(503)
		}
		io.WriteString(w, "native-diagnostic-response")
	}))
	defer web.Close()
	endpoint := func(address string) engine.Endpoint {
		host, port, e := net.SplitHostPort(address)
		if e != nil {
			t.Fatal(e)
		}
		n, _ := strconv.Atoi(port)
		return engine.Endpoint{Host: host, Port: n}
	}
	sequence := 0
	call := func(q Diagnostic) (protocol.Command, protocol.Result, map[string]any) {
		t.Helper()
		sequence++
		payload, _ := json.Marshal(q)
		command := protocol.Command{ID: "diagnostic_" + strconv.Itoa(sequence), Kind: "diagnostic", Payload: payload, Expires: time.Now().Add(time.Minute)}
		result := r.Execute(context.Background(), command)
		var data map[string]any
		json.Unmarshal(result.Data, &data)
		return command, result, data
	}
	passed := func(result protocol.Result, data map[string]any) {
		t.Helper()
		if !result.OK || data["status"] != "passed" || data["target"] == "" || data["duration_ms"] == nil {
			t.Fatalf("real diagnostic failed: %s %v", result.Code, data["status"])
		}
	}
	_, result, data := call(Diagnostic{Kind: "tcp", Endpoint: endpoint(web.Listener.Addr().String())})
	passed(result, data)
	command, result, data := call(Diagnostic{Kind: "http", Endpoint: endpoint(web.Listener.Addr().String()), Path: "/probe", Expected: "native-diagnostic-response"})
	passed(result, data)
	// Reconstruct the executor against persisted state. A delivery retry must
	// return its receipt without sending another actual HTTP request.
	restarted := &Runtime{StateDir: r.StateDir, ConfigDir: r.ConfigDir}
	if !restarted.Execute(context.Background(), command).OK || requests.Load() != 1 {
		t.Fatal("persisted receipt re-executed an actual request")
	}
	changed := command
	changed.Payload = json.RawMessage(`{"kind":"http","endpoint":{"host":"127.0.0.1","port":1}}`)
	if v := restarted.Execute(context.Background(), changed); v.OK || v.Code != "command_identity_conflict" || requests.Load() != 1 {
		t.Fatal("changed retry payload was accepted")
	}
	_, result, data = call(Diagnostic{Kind: "http", Endpoint: endpoint(web.Listener.Addr().String()), Path: "/bad"})
	if !result.OK || data["status"] != "failed" {
		t.Fatal("HTTP 503 was reported healthy")
	}
	tlsWeb := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {}))
	defer tlsWeb.Close()
	trust := filepath.Join(r.ConfigDir, "certificates", "diagnostic_trust")
	os.MkdirAll(trust, 0700)
	os.WriteFile(filepath.Join(trust, "cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsWeb.Certificate().Raw}), 0600)
	_, result, data = call(Diagnostic{Kind: "tls", Endpoint: endpoint(tlsWeb.Listener.Addr().String()), CA: "diagnostic_trust"})
	passed(result, data)
	if data["verified"] != true {
		t.Fatal("TLS identity was not verified")
	}
	if tlsWeb.Certificate().VerifyHostname("rejected.invalid") == nil {
		t.Fatal("negative TLS fixture unexpectedly matches the certificate")
	}
	_, result, data = call(Diagnostic{Kind: "tls", Endpoint: endpoint(tlsWeb.Listener.Addr().String()), CA: "diagnostic_trust", ServerName: "rejected.invalid"})
	if !result.OK || data["status"] != "failed" {
		t.Fatal("wrong TLS hostname was accepted")
	}
	echo, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer echo.Close()
	go func() {
		for {
			conn, e := echo.Accept()
			if e != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				io.CopyN(c, c, 65536)
			}(conn)
		}
	}()
	_, result, data = call(Diagnostic{Kind: "echo", Endpoint: endpoint(echo.Addr().String())})
	passed(result, data)
	if data["bytes"] != float64(128) {
		t.Fatal("echo exceeded its fixed sample")
	}
	_, result, _ = call(Diagnostic{Kind: "speed", Endpoint: endpoint(echo.Addr().String()), Bytes: 65536})
	if result.OK || result.Code != "explicit_speed_test_confirmation_required" {
		t.Fatal("speed traffic ran without explicit confirmation")
	}
	_, result, data = call(Diagnostic{Kind: "speed", Endpoint: endpoint(echo.Addr().String()), Bytes: 65536, Confirm: true})
	passed(result, data)
	if data["bytes"] != float64(65536) || data["scope"] != "one bounded echo sample, not link capacity" {
		t.Fatal("speed sample scope/limit lost")
	}
	_, result, data = call(Diagnostic{Kind: "speed", Endpoint: endpoint(echo.Addr().String()), Bytes: 65537, Confirm: true})
	passed(result, data)
	if data["bytes"] != float64(32768) {
		t.Fatal("oversized requested sample was not bounded")
	}
	_, result, data = call(Diagnostic{Kind: "ping", Endpoint: engine.Endpoint{Host: "127.0.0.1", Port: 1}})
	passed(result, data)
	if data["packets"] != float64(3) {
		t.Fatal("ping packet limit lost")
	}
	command.Expires = time.Now().Add(-time.Second)
	if v := restarted.Execute(context.Background(), command); v.OK || v.Code != "expired_or_invalid_command" {
		t.Fatal("expired replay accepted")
	}
	t.Log("Actual Linux TCP/TLS/HTTP/ping/128-byte echo/64KiB confirmed sample; bad hostname/HTTP503 rejected; persisted receipt and immutable/expired retry checks passed")
}
