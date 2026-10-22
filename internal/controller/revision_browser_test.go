package controller

import (
	"context"
	"encoding/json"
	"github.com/itsHesamHoseini/TunnelManager/internal/engine"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestRevisionHonestyBrowser(t *testing.T) {
	if os.Getenv("TUNNELMANAGER_BROWSER_TESTS") != "1" {
		t.Skip("real Chrome requires opt-in and isolated PostgreSQL")
	}
	s, srv, c := testServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	conn := fixtureNode(t, s, srv, c, ctx)
	defer conn.CloseNow()
	s.DB.Exec(ctx, "UPDATE nodes SET name='نمونه ایران متصل' WHERE id='live-fixture'")
	data, _ := json.Marshal(map[string]any{"at": time.Now(), "os": "Ubuntu sample", "cpu_percent": 95, "ram_used": 95, "ram_total": 100, "disk_total": 100, "disk_free": 5})
	for _, node := range []struct{ id, name, age string }{
		{"disconnected", "نمونه خارج قطع", "1 second"},
		{"stale", "نمونه ایران قدیمی", "10 minutes"},
		{"missing", "نمونه بدون داده", "10 minutes"},
	} {
		observed := data
		if node.id == "missing" {
			observed = []byte("{}")
		}
		if _, e := s.DB.Exec(ctx, "INSERT INTO nodes(id,name,role,pubkey,approved,seen,telemetry)VALUES($1,$2,'iran',$3,true,now()-$4::interval,$5)", node.id, node.name, make([]byte, 32), node.age, observed); e != nil {
			t.Fatal(e)
		}
	}
	s.Audit(ctx, "operation-failed", "disconnected", "inventory · node_offline")
	s.Audit(ctx, "unknown_internal_event", "missing", "unknown_private_reason")
	s.DB.Exec(ctx, "INSERT INTO alerts(rule,target,severity,code)VALUES('offline','stale','warning','node_observation_stale')")
	if os.Getenv("TUNNELMANAGER_REVISION_BEFORE") != "1" {
		for _, name := range []string{"backhaul", retiredEngineName} {
			id, title, instance := "supported_sample", "نمونه تونل ایران به خارج", "supported_instance"
			if name != "backhaul" {
				id, title, instance = "retired_sample", "نمونه کنارگذاشته‌شده", "retired_instance"
			}
			spec := engine.Spec{Engine: name, Version: "0.7.2", Transport: "tcp", Listener: "live-fixture", Dialer: "disconnected", TransportBind: engine.Endpoint{Host: "0.0.0.0", Port: 28100}, TransportRemote: engine.Endpoint{Host: "192.0.2.10", Port: 28100}, Token: "synthetic-only-token", Routes: []engine.Route{{ID: "route1", Name: "نمونه نگاشت", User: engine.Endpoint{Host: "0.0.0.0", Port: 24443}, Backend: engine.Endpoint{Host: "127.0.0.1", Port: 2096}, Protocol: "tcp"}}}
			cipher, _ := s.sealValue("tunnel:"+id, TunnelRecord{Spec: spec, Instances: map[string]string{"live-fixture": instance, "disconnected": instance + "_peer"}})
			if _, e := s.DB.Exec(ctx, "INSERT INTO tunnels(id,name,cipher)VALUES($1,$2,$3)", id, title, cipher); e != nil {
				t.Fatal(e)
			}
		}
		inventory, _ := json.Marshal(map[string]any{"instances": []map[string]any{{"id": "supported_instance", "name": "نمونه سرویس مدیریت‌پذیر", "engine": "backhaul", "version": "0.7.2", "role": "server", "active": "active"}, {"id": "retired_instance", "name": "نمونه کنارگذاشته‌شده", "engine": retiredEngineName, "role": "server"}}})
		s.DB.Exec(ctx, "UPDATE nodes SET inventory=$1,inventory_at=now() WHERE id='live-fixture'", inventory)
		report, e := s.RetireEngine(ctx, filepath.Join(t.TempDir(), "before.backup"))
		if e != nil {
			t.Fatal(e)
		}
		t.Logf("Sample-only migration: services 2 -> 1, observation tunnels 2 -> 1, managed 0 -> 0; removed %d tunnel and %d service; no host action", report.Tunnels, report.Services)
	}
	cmd := exec.Command("node", "web/tests/revision-honesty.mjs")
	cmd.Dir = filepath.Join("..", "..")
	cmd.Env = append(os.Environ(), "TUNNELMANAGER_TEST_URL="+srv.URL)
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("revision browser: %v\n%s", e, out)
	} else {
		t.Log(string(out))
	}
}
