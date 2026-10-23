package controller

import (
	"context"
	"encoding/json"
	"github.com/itsHesamHoseini/TunnelManager/internal/engine"
	"testing"
)

func TestEntryCheckTargetsActualMappingNotTransportOrBackend(t *testing.T) {
	spec := sharedSpec("client", "entry", 24443)
	source, target, err := entryTarget(spec, "entry")
	if err != nil || source != "client" || target.Host != spec.TransportRemote.Host || target.Port != 24443 {
		t.Fatal("not targeting user entry")
	}
	spec.Routes[0].User.Host = "127.0.0.1"
	source, target, err = entryTarget(spec, "entry")
	if err != nil || source != "listener" || target.Host != "127.0.0.1" {
		t.Fatal("loopback entry tested from wrong host")
	}
	if _, _, err = entryTarget(spec, "missing"); err == nil {
		t.Fatal("unknown mapping accepted")
	}
	s, srv, c := testServer(t)
	enrollMFA(t, srv, c)
	ctx := context.Background()
	cipher, _ := s.sealValue("tunnel:entry", TunnelRecord{Spec: spec})
	s.DB.Exec(ctx, "INSERT INTO tunnels(id,name,cipher)VALUES('entry','Synthetic entry',$1)", cipher)
	for _, bad := range []map[string]any{{"Kind": "http", "ExpectedRevision": 1}, {"Kind": "tls", "ExpectedRevision": 2}, {"Kind": "tls", "ExpectedRevision": 1, "ServerName": "bad/host"}} {
		bad["RequestKey"] = "bad_entry"
		bad["Mapping"] = "entry"
		status, _ := request(t, c, srv.URL+"/api/tunnels/entry/entry-check", "POST", bad)
		if status == 200 {
			t.Fatal("unsafe entry request accepted")
		}
	}
	status, body := request(t, c, srv.URL+"/api/tunnels/entry/entry-check", "POST", map[string]any{"RequestKey": "valid_entry", "Mapping": "entry", "Kind": "tcp", "ExpectedRevision": 1})
	if status != 200 {
		t.Fatal("bounded entry request rejected")
	}
	var raw []byte
	var q JobPayload
	id := body["operation_id"].(string)
	s.DB.QueryRow(ctx, "SELECT cipher FROM operations WHERE id=$1", id).Scan(&raw)
	s.openValue("operation:"+id, raw, &q)
	var diagnostic struct {
		Kind     string          `json:"kind"`
		Endpoint engine.Endpoint `json:"endpoint"`
	}
	json.Unmarshal(q.Payload, &diagnostic)
	if diagnostic.Kind != "tcp" || diagnostic.Endpoint.Port != 24443 || q.Node != "listener" {
		t.Fatal("durable job changed entry scope")
	}
	s.DB.Exec(ctx, "UPDATE tunnels SET revision=revision+1 WHERE id='entry'")
	s.processEntryCheck(ctx, id, q)
	var phase string
	var commands int
	s.DB.QueryRow(ctx, "SELECT phase FROM operations WHERE id=$1", id).Scan(&phase)
	s.DB.QueryRow(ctx, "SELECT count(*) FROM commands WHERE operation_id=$1", id).Scan(&commands)
	if phase != "failed" || commands != 0 {
		t.Fatal("stale revision queued entry probe")
	}
}
