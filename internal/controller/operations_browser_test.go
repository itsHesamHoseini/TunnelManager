package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/itsHesamHoseini/TunnelManager/internal/engine"
	"github.com/itsHesamHoseini/TunnelManager/internal/nodeops"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestOperationalPagesInBrowser(t *testing.T) {
	if os.Getenv("TUNNELMANAGER_BROWSER_TESTS") != "1" {
		t.Skip("browser opt-in")
	}
	s, srv, _ := testServer(t)
	ctx := context.Background()
	for _, node := range []string{"listener", "dialer"} {
		s.DB.Exec(ctx, "INSERT INTO nodes(id,name,role,pubkey,approved,protocol,seen)VALUES($1,$2,'foreign',$3,true,2,now())", node, "Synthetic "+node, make([]byte, 32))
	}
	for i, status := range []string{"passed", "failed", "unknown", "stale"} {
		id := "synthetic_" + status
		spec := engine.Spec{Engine: "backhaul", Version: "0.7.2", Transport: "tcp", Listener: "listener", Dialer: "dialer", TransportBind: engine.Endpoint{Host: "0.0.0.0", Port: 28100 + i}, TransportRemote: engine.Endpoint{Host: "192.0.2.10", Port: 28100 + i}, Routes: []engine.Route{{ID: "route1", Name: "Synthetic route", User: engine.Endpoint{Host: "0.0.0.0", Port: 24443 + i}, Backend: engine.Endpoint{Host: "127.0.0.1", Port: 2096}, Protocol: "tcp"}}}
		engine.GenerateSecrets(&spec)
		rec := TunnelRecord{Spec: spec, Instances: map[string]string{"listener": "synthetic_server", "dialer": "synthetic_client"}, Hashes: map[string]string{"listener": "hash1", "dialer": "hash2"}}
		cipher, _ := s.sealValue("tunnel:"+id, rec)
		at := time.Now()
		if status == "stale" {
			at = at.Add(-10 * time.Minute)
			status = "passed"
		}
		health, _ := json.Marshal(map[string]any{"at": at, "process": []map[string]any{{"status": status}, {"status": status}}, "transport": map[string]any{"status": status, "source": "dialer"}, "application": map[string]any{"status": "unconfigured"}})
		s.DB.Exec(ctx, "INSERT INTO tunnels(id,name,cipher,managed,health)VALUES($1,$2,$3,true,$4)", id, "Synthetic "+id, cipher, health)
	}
	inventory, _ := json.Marshal(map[string]any{"instances": []nodeops.Discovered{{Instance: nodeops.Instance{ID: "synthetic_server", Name: "Synthetic shared service", Unit: "backhaul-synthetic.service", Engine: "backhaul", Version: "0.7.2", Role: "server", Managed: true}, Parsed: engine.Parsed{Role: "server", Transport: "tcp", Bind: "0.0.0.0:28100"}, Configuration: "[server]\nbind_addr='0.0.0.0:28100'\ntoken='[redacted]'\n", Active: "active"}}})
	s.DB.Exec(ctx, "UPDATE nodes SET inventory=$1,inventory_at=now() WHERE id='listener'", inventory)
	// Reproduce same-named service/linked tunnel and peer ambiguity in the fast
	// browser suite; the native tests reuse the exact same selection helpers.
	s.DB.Exec(ctx, "UPDATE tunnels SET name='Synthetic shared service' WHERE id='synthetic_unknown'")
	s.DB.Exec(ctx, "UPDATE nodes SET inventory=$1,inventory_at=now() WHERE id='dialer'", inventory)
	configurationJob, _ := s.newJob(ctx, "fixture_config", "node", "listener", "Fixture redacted configuration", JobPayload{Node: "listener", Kind: "instance.config"})
	configurationResult, _ := json.Marshal(map[string]any{"configuration": "[server]\nbind_addr='0.0.0.0:28100'\ntoken='[redacted]'\n"})
	s.DB.Exec(ctx, "UPDATE operations SET phase='succeeded',result=$1 WHERE id=$2", configurationResult, configurationJob)
	diagnostic, _ := s.newJob(ctx, "fixture_diagnostic", "node", "listener", "Fixture diagnostic failed", JobPayload{Node: "listener", Kind: "diagnostic", Payload: json.RawMessage(`{"kind":"tcp","endpoint":{"host":"192.0.2.10","port":443}}`)})
	result, _ := json.Marshal(map[string]any{"status": "failed", "kind": "tcp", "target": "192.0.2.10:443", "at": time.Now(), "code": "connection_or_protocol_check_failed"})
	s.DB.Exec(ctx, "UPDATE operations SET phase='succeeded',result=$1 WHERE id=$2", result, diagnostic)
	s.newJob(ctx, "fixture_queued", "node", "listener", "Fixture queued operation", JobPayload{Node: "listener", Kind: "inventory"})
	for i := 0; i < 10; i++ {
		data, _ := json.Marshal(map[string]any{"os": "Synthetic Ubuntu 24.04", "cpu_percent": float64(10 + i*6), "ram_used": (i + 1) * 67108864, "ram_total": 1073741824, "disk_free": (i + 1) * 1073741824})
		s.DB.Exec(ctx, "INSERT INTO nodes(id,name,role,pubkey,approved,seen,telemetry)VALUES($1,$2,'foreign',$3,true,now(),$4)", fmt.Sprintf("preview-%d", i), fmt.Sprintf("Fixture server %02d", i+1), make([]byte, 32), data)
	}
	data, _ := json.Marshal(map[string]any{"os": "Synthetic Ubuntu 24.04", "cpu_percent": 17.5, "ram_used": 268435456, "ram_total": 1073741824, "disk_free": 5368709120, "disk_total": 10737418240})
	s.DB.Exec(ctx, "UPDATE nodes SET telemetry=$1 WHERE id IN('listener','dialer')", data)
	for i := 0; i < 12; i++ {
		sample, _ := json.Marshal(map[string]any{"cpu_percent": float64(15 + i), "ram_used": 268435456 + i*1048576, "disk_free": 5368709120})
		s.DB.Exec(ctx, "INSERT INTO measurements(node_id,at,data)VALUES('listener',now()-$1*interval '30 seconds',$2)", i, sample)
	}
	if os.Getenv("TUNNELMANAGER_PREVIEW") == "1" {
		// Local-only, synthetic preview. Production authentication and TLS are unchanged.

		u, _ := url.Parse(srv.URL)
		proxy := httputil.NewSingleHostReverseProxy(u)
		proxy.Transport = srv.Client().Transport
		director := proxy.Director
		proxy.Director = func(r *http.Request) {
			director(r)
			if r.Header.Get("Origin") != "" {
				r.Header.Set("Origin", srv.URL)
			}
		}
		preview := httptest.NewServer(proxy)
		defer preview.Close()
		os.MkdirAll(filepath.Join("..", "..", ".runtime"), 0700)
		os.WriteFile(filepath.Join("..", "..", ".runtime", "console-preview-url"), []byte(preview.URL), 0600)
		t.Log("Synthetic console preview ready on loopback; URL is in .runtime/console-preview-url")
		<-time.After(25 * time.Minute)
		return
	}
	cmd := exec.Command("node", "web/tests/operations.mjs")
	cmd.Dir = filepath.Join("..", "..")
	cmd.Env = append(os.Environ(), "TUNNELMANAGER_TEST_URL="+srv.URL)
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("operational browser: %v\n%s", e, out)
	}
}
