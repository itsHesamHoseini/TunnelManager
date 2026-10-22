package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/itsHesamHoseini/TunnelManager/internal/secure"
	"github.com/jackc/pgx/v5"
	"strings"
)

func TestRetirementMixedDatabaseBackupAndDependencies(t *testing.T) {
	s, _, _ := testServer(t)
	ctx := context.Background()
	for _, node := range []string{"entry", "peer"} {
		if _, e := s.DB.Exec(ctx, "INSERT INTO nodes(id,name,role,pubkey,approved)VALUES($1,$1,'iran',$2,true)", node, make([]byte, 32)); e != nil {
			t.Fatal(e)
		}
	}
	var keptCipher []byte
	for _, engineName := range []string{retiredEngineName, "backhaul"} {
		id := "retired"
		instance := "retired_instance"
		if engineName == "backhaul" {
			id = "kept"
			instance = "kept_instance"
		}
		rec := map[string]any{"spec": map[string]any{"engine": engineName, "token": "synthetic-retirement-secret"}, "instances": map[string]string{"entry": instance, "peer": instance + "_peer"}}
		cipher, e := s.sealValue("tunnel:"+id, rec)
		if e != nil {
			t.Fatal(e)
		}
		if id == "kept" {
			keptCipher = cipher
		}
		if _, e = s.DB.Exec(ctx, "INSERT INTO tunnels(id,name,cipher,managed)VALUES($1,$1,$2,true)", id, cipher); e != nil {
			t.Fatal(e)
		}
		if _, e = s.DB.Exec(ctx, "INSERT INTO tunnel_versions(tunnel_id,revision,cipher)VALUES($1,1,$2)", id, cipher); e != nil {
			t.Fatal(e)
		}
	}
	inv, _ := json.Marshal(map[string]any{"instances": []any{map[string]any{"id": "retired_instance", "engine": retiredEngineName}, map[string]any{"id": "kept_instance", "engine": "backhaul"}}})
	s.DB.Exec(ctx, "UPDATE nodes SET inventory=$1 WHERE id='entry'", inv)
	s.DB.Exec(ctx, "INSERT INTO certificates(id,name,domain,cipher,not_after,issuer,method)VALUES('cert','Synthetic','example.test',$1,now()+interval '1 day','synthetic','self-signed')", []byte("certificate-unchanged"))
	for _, instance := range []string{"retired_instance", "kept_instance"} {
		s.DB.Exec(ctx, "INSERT INTO certificate_links(certificate_id,node_id,instance_id,trust_only)VALUES('cert','entry',$1,false)", instance)
		s.DB.Exec(ctx, "INSERT INTO recovery_rules(node_id,instance_id,policy)VALUES('entry',$1,'{}')", instance)
	}
	for _, id := range []string{"retired_job", "kept_job", "mixed_job"} {
		target := "retired"
		var payload any = map[string]any{"spec": map[string]any{"engine": retiredEngineName}}
		if id == "kept_job" {
			target = "kept"
			payload = map[string]any{"spec": map[string]any{"engine": "backhaul"}}
		}
		if id == "mixed_job" {
			target = "batch"
			payload = map[string]any{"parts": []any{map[string]any{"engine": retiredEngineName, "instance": "retired_instance"}, map[string]any{"engine": "backhaul", "instance": "kept_instance"}}}
		}
		cipher, _ := s.sealValue("operation:"+id, payload)
		if _, e := s.DB.Exec(ctx, "INSERT INTO operations(id,request_key,kind,target,name,phase,cipher)VALUES($1,$1,'plan',$2,$1,'succeeded',$3)", id, target, cipher); e != nil {
			t.Fatal(e)
		}
		s.DB.Exec(ctx, "INSERT INTO port_reservations(plan_id,node_id,host,port,protocol,expires)VALUES($1,'entry','0.0.0.0',$2,'tcp',now()+interval '1 day')", id, 30000+len(id))
	}
	backup := filepath.Join(t.TempDir(), "before.backup")
	report, e := s.RetireEngine(ctx, backup)
	if e != nil {
		t.Fatal(e)
	}
	if report.Tunnels != 1 || report.Services != 1 || report.Operations != 1 {
		t.Fatalf("unexpected counts %+v", report)
	}
	var after []byte
	if e = s.DB.QueryRow(ctx, "SELECT cipher FROM tunnels WHERE id='kept'").Scan(&after); e != nil || !bytes.Equal(after, keptCipher) {
		t.Fatal("supported tunnel modified")
	}
	for _, query := range []string{"SELECT count(*) FROM tunnel_versions WHERE tunnel_id='retired'", "SELECT count(*) FROM certificate_links WHERE instance_id='retired_instance'", "SELECT count(*) FROM recovery_rules WHERE instance_id='retired_instance'", "SELECT count(*) FROM port_reservations WHERE plan_id='retired_job'"} {
		var n int
		if e = s.DB.QueryRow(ctx, query).Scan(&n); e != nil || n != 0 {
			t.Fatal("retired dependency remains", query, e)
		}
	}
	for _, query := range []string{"SELECT count(*) FROM tunnel_versions WHERE tunnel_id='kept'", "SELECT count(*) FROM certificate_links WHERE instance_id='kept_instance'", "SELECT count(*) FROM recovery_rules WHERE instance_id='kept_instance'", "SELECT count(*) FROM port_reservations WHERE plan_id='kept_job'"} {
		var n int
		if e = s.DB.QueryRow(ctx, query).Scan(&n); e != nil || n != 1 {
			t.Fatal("supported dependency changed", query, e)
		}
	}
	var mixed []byte
	s.DB.QueryRow(ctx, "SELECT cipher FROM operations WHERE id='mixed_job'").Scan(&mixed)
	raw, e := secure.Open(s.Config.Key, "operation:mixed_job", mixed)
	if e != nil || bytes.Contains(raw, []byte(retiredEngineName)) || !bytes.Contains(raw, []byte("kept_instance")) {
		t.Fatal("mixed history was lost or not pruned")
	}
	sealed, e := os.ReadFile(backup)
	if e != nil || bytes.Contains(sealed, []byte("synthetic-retirement-secret")) {
		t.Fatal("backup unavailable or plaintext")
	}
	var originals []json.RawMessage
	if e = verifyRetirementBackup(backup, s.Config.Key, func(table string, row json.RawMessage) error {
		if table == "tunnels" {
			originals = append(originals, append(json.RawMessage{}, row...))
		}
		return nil
	}); e != nil {
		t.Fatal("backup cannot be authenticated", e)
	}
	if len(originals) != 2 {
		t.Fatal("snapshot not taken before deletion")
	}
	// Restore every typed row into another isolated schema and authenticate the
	// complete final frame before committing. This is backup evidence, not a
	// production restore endpoint or a silent reverse migration.
	restored, _, _ := testServer(t)
	rtx, e := restored.DB.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer rtx.Rollback(ctx)
	tables := []string{}
	for _, table := range ownedTables {
		tables = append(tables, pgx.Identifier{table}.Sanitize())
	}
	if _, e = rtx.Exec(ctx, "TRUNCATE "+strings.Join(tables, ",")+" RESTART IDENTITY CASCADE"); e != nil {
		t.Fatal(e)
	}
	if e = verifyRetirementBackup(backup, s.Config.Key, func(table string, row json.RawMessage) error {
		_, err := rtx.Exec(ctx, "INSERT INTO "+pgx.Identifier{table}.Sanitize()+" SELECT * FROM json_populate_record(NULL::"+pgx.Identifier{table}.Sanitize()+",$1::json)", row)
		return err
	}); e != nil {
		t.Fatal("actual typed backup restore failed", e)
	}
	if e = rtx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	var restoredCount int
	if e = restored.DB.QueryRow(ctx, "SELECT count(*) FROM tunnels").Scan(&restoredCount); e != nil || restoredCount != 2 {
		t.Fatal("restored mixed rows missing")
	}
	var restoredCipher []byte
	restored.DB.QueryRow(ctx, "SELECT cipher FROM tunnels WHERE id='kept'").Scan(&restoredCipher)
	if !bytes.Equal(restoredCipher, keptCipher) {
		t.Fatal("restored supported ciphertext changed")
	}
	damaged := append([]byte{}, sealed...)
	damaged[len(damaged)/2] ^= 1
	bad := filepath.Join(t.TempDir(), "damaged.backup")
	os.WriteFile(bad, damaged, 0600)
	if verifyRetirementBackup(bad, s.Config.Key, nil) == nil {
		t.Fatal("damaged snapshot accepted")
	}
	os.WriteFile(bad, sealed[:len(sealed)-10], 0600)
	if verifyRetirementBackup(bad, s.Config.Key, nil) == nil {
		t.Fatal("truncated snapshot accepted")
	}

	second, e := s.RetireEngine(ctx, backup)
	if e != nil || !second.AlreadyApplied {
		t.Fatal("migration not one-way/idempotent")
	}
}

func TestRetirementControllerRejectsUnsupportedActionsBeforeOlderAgent(t *testing.T) {
	s, _, _ := testServer(t)
	ctx := context.Background()
	inventory, _ := json.Marshal(map[string]any{"instances": []map[string]any{{"id": "old_instance", "engine": retiredEngineName}, {"id": "kept_instance", "engine": "backhaul"}}})
	s.DB.Exec(ctx, "INSERT INTO nodes(id,name,role,pubkey,approved,protocol,inventory,inventory_at)VALUES('older','Synthetic older agent','iran',$1,true,2,$2,now())", make([]byte, 32), inventory)
	for _, tc := range []struct {
		kind    string
		payload any
	}{{"engine.install", map[string]string{"Engine": retiredEngineName, "Version": "0.5.0"}}, {"instance.adopt", map[string]string{"ID": "old_instance"}}, {"instance.action", map[string]string{"ID": "old_instance", "Action": "restart"}}, {"recovery.policy", map[string]any{"ID": "old_instance", "Enabled": true}}} {
		body, _ := json.Marshal(map[string]any{"request_key": "retirement_" + strings.ReplaceAll(tc.kind, ".", "_"), "kind": tc.kind, "confirm": true, "payload": tc.payload})
		r := httptest.NewRequest("POST", "/api/nodes/older/actions", bytes.NewReader(body))
		r.SetPathValue("id", "older")
		w := httptest.NewRecorder()
		s.nodeAction(w, r)
		if w.Code != 400 {
			t.Fatalf("unsupported %s could be queued for an older agent: %d", tc.kind, w.Code)
		}
	}
	var jobs int
	s.DB.QueryRow(ctx, "SELECT count(*) FROM operations").Scan(&jobs)
	if jobs != 0 {
		t.Fatal("unsupported action reached durable queue")
	}
	allowed, _ := json.Marshal(map[string]any{"request_key": "supported_install", "kind": "engine.install", "confirm": true, "payload": map[string]string{"Engine": "backhaul", "Version": "0.7.2"}})
	r := httptest.NewRequest("POST", "/api/nodes/older/actions", bytes.NewReader(allowed))
	r.SetPathValue("id", "older")
	w := httptest.NewRecorder()
	s.nodeAction(w, r)
	if w.Code != 200 {
		t.Fatal("valid Backhaul action was blocked", w.Code)
	}
}

func TestRetirementBackupFailureAndPendingBlockNoChanges(t *testing.T) {
	s, _, _ := testServer(t)
	ctx := context.Background()
	cipher, _ := s.sealValue("tunnel:retired", map[string]any{"spec": map[string]any{"engine": retiredEngineName}})
	s.DB.Exec(ctx, "INSERT INTO tunnels(id,name,cipher)VALUES('retired','Synthetic',$1)", cipher)
	if _, e := s.RetireEngine(ctx, "relative.backup"); e == nil {
		t.Fatal("migration ignored unavailable backup")
	}
	var n int
	s.DB.QueryRow(ctx, "SELECT count(*) FROM tunnels WHERE id='retired'").Scan(&n)
	if n != 1 {
		t.Fatal("backup failure changed database")
	}
	job, _ := s.sealValue("operation:pending", map[string]any{})
	s.DB.Exec(ctx, "INSERT INTO operations(id,request_key,kind,name,cipher,phase)VALUES('pending','pending','plan','Synthetic',$1,'awaiting_confirmation')", job)
	path := filepath.Join(t.TempDir(), "before.backup")
	if _, e := s.RetireEngine(ctx, path); e == nil {
		t.Fatal("pending rollback ignored")
	}
	if _, e := os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("pending operation should block before backup/mutation")
	}
	s.DB.Exec(ctx, "DELETE FROM operations WHERE id='pending'")
	readOnly, _ := s.sealValue("operation:read_only", JobPayload{Kind: "inventory", Node: "synthetic"})
	s.DB.Exec(ctx, "INSERT INTO operations(id,request_key,kind,name,cipher,phase)VALUES('read_only','read_only','node','Synthetic read-only discovery',$1,'queued')", readOnly)
	if _, e := s.RetireEngine(ctx, path); e != nil {
		t.Fatal("read-only monitoring incorrectly blocks retirement", e)
	}
	var remaining int
	s.DB.QueryRow(ctx, "SELECT count(*) FROM operations WHERE id='read_only'").Scan(&remaining)
	if remaining != 1 {
		t.Fatal("unrelated read-only operation discarded")
	}
}

func TestRetirementSameLocalIDOnDifferentNodesAndExactNumbers(t *testing.T) {
	s, _, _ := testServer(t)
	ctx := context.Background()
	for _, node := range []string{"old_entry", "old_peer", "kept_entry", "kept_peer"} {
		if _, e := s.DB.Exec(ctx, "INSERT INTO nodes(id,name,role,pubkey,approved)VALUES($1,$1,'iran',$2,true)", node, make([]byte, 32)); e != nil {
			t.Fatal(e)
		}
	}
	for _, tc := range []struct{ id, name, entry, peer string }{{"old", retiredEngineName, "old_entry", "old_peer"}, {"kept", "backhaul", "kept_entry", "kept_peer"}} {
		spec := sharedSpec(tc.peer, "one", 24443)
		spec.Engine = tc.name
		spec.Listener = tc.entry
		cipher, _ := s.sealValue("tunnel:"+tc.id, TunnelRecord{Spec: spec, Instances: map[string]string{tc.entry: "same_local_id", tc.peer: "same_peer_id"}})
		if _, e := s.DB.Exec(ctx, "INSERT INTO tunnels(id,name,cipher)VALUES($1,$1,$2)", tc.id, cipher); e != nil {
			t.Fatal(e)
		}
		job := JobPayload{Node: tc.entry, Kind: "instance.action", Payload: json.RawMessage(`{"ID":"same_local_id","Action":"stop"}`)}
		cipher, _ = s.sealValue("operation:"+tc.id+"_job", job)
		s.DB.Exec(ctx, "INSERT INTO operations(id,request_key,name,kind,phase,cipher)VALUES($1,$1,$1,'node','succeeded',$2)", tc.id+"_job", cipher)
	}
	// Force a telemetry rewrite while retaining a number above IEEE-754's exact
	// integer range. A generic float64 JSON decode would silently corrupt it.
	telemetry := `{"counter":9007199254740993,"listeners":[{"address":"127.0.0.1:24443","process":"` + retiredEngineName + `-old"}]}`
	s.DB.Exec(ctx, "UPDATE nodes SET telemetry=$1 WHERE id='kept_entry'", []byte(telemetry))
	if _, e := s.RetireEngine(ctx, filepath.Join(t.TempDir(), "before.backup")); e != nil {
		t.Fatal("node-scoped instance IDs should not conflict", e)
	}
	var n int
	s.DB.QueryRow(ctx, "SELECT count(*) FROM operations WHERE id='old_job'").Scan(&n)
	if n != 0 {
		t.Fatal("retired scoped job retained")
	}
	s.DB.QueryRow(ctx, "SELECT count(*) FROM operations WHERE id='kept_job'").Scan(&n)
	if n != 1 {
		t.Fatal("supported scoped job removed")
	}
	var counter string
	s.DB.QueryRow(ctx, "SELECT telemetry->>'counter' FROM nodes WHERE id='kept_entry'").Scan(&counter)
	if counter != "9007199254740993" {
		t.Fatal("large measured counter changed")
	}
}
