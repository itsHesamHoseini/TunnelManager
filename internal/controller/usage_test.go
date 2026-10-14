package controller

import (
	"context"
	"encoding/json"
	"github.com/itsHesamHoseini/TunnelManager/internal/protocol"
	"testing"
	"time"
)

func TestUsageScopeResetAndCAS(t *testing.T) {
	s, srv, c := testServer(t)
	enrollMFA(t, srv, c)
	id := "synthetic-usage"
	pub := make([]byte, 32)
	s.DB.Exec(context.Background(), "INSERT INTO nodes(id,name,role,pubkey,approved)VALUES($1,'Example synthetic','iran',$2,true)", id, pub)
	old := protocol.Telemetry{At: time.Now().Add(-time.Minute), Boot: "fixture-boot", Networks: []protocol.Network{{Name: "eth0", Primary: true, RX: 100, TX: 200}, {Name: "lo", RX: 999, TX: 999}}}
	current := old
	current.At = time.Now()
	current.Networks = []protocol.Network{{Name: "eth0", Primary: true, RX: 300, TX: 500}, {Name: "lo", RX: 999999, TX: 999999}}
	previous, _ := json.Marshal(old)
	tx, _ := s.DB.Begin(context.Background())
	if e := recordUsage(context.Background(), tx, id, previous, &current); e != nil {
		t.Fatal(e)
	}
	tx.Commit(context.Background())
	u := s.usage(context.Background(), id)
	if u["rx"] != int64(200) || u["tx"] != int64(300) {
		t.Fatal("wrong NIC scope", u)
	}
	current.Boot = "different-boot"
	tx, _ = s.DB.Begin(context.Background())
	recordUsage(context.Background(), tx, id, previous, &current)
	tx.Commit(context.Background())
	if s.usage(context.Background(), id)["rx"] != int64(200) {
		t.Fatal("reboot counters counted")
	}
	status, _ := request(t, c, srv.URL+"/api/nodes/"+id, "PUT", map[string]any{"name": "Example updated", "role": "iran", "expected_revision": 1})
	if status != 200 {
		t.Fatal(status)
	}
	status, _ = request(t, c, srv.URL+"/api/nodes/"+id, "PUT", map[string]any{"name": "Stale overwrite", "role": "iran", "expected_revision": 1})
	if status != 409 {
		t.Fatal("stale overwrite accepted")
	}
}
