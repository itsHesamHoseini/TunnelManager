package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/coder/websocket"
	"github.com/itsHesamHoseini/TunnelManager/internal/engine"
	"github.com/itsHesamHoseini/TunnelManager/internal/nodeops"
	"github.com/itsHesamHoseini/TunnelManager/internal/protocol"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Real signed protocol connection, with canned command receipts only for model
// safety tests. This is not a Linux/systemd/engine-effect acceptance test.
func connectedAdoptionFixture(t *testing.T, s *Server, srv *httptest.Server, id string, ctx context.Context) *websocket.Conn {
	t.Helper()
	pub, private, _ := ed25519.GenerateKey(rand.Reader)
	if _, e := s.DB.Exec(ctx, "INSERT INTO nodes(id,name,role,pubkey,approved)VALUES($1,$1,'foreign',$2,true)", id, pub); e != nil {
		t.Fatal(e)
	}
	conn, _, e := websocket.Dial(ctx, "wss"+srv.URL[5:]+"/api/agent", &websocket.DialOptions{HTTPClient: srv.Client()})
	if e != nil {
		t.Fatal(e)
	}
	_, raw, e := conn.Read(ctx)
	if e != nil {
		t.Fatal(e)
	}
	var hello protocol.Hello
	json.Unmarshal(raw, &hello)
	proof := id + "\n" + hello.Nonce + "\n" + hello.Expires.UTC().Format(time.RFC3339Nano)
	raw, _ = json.Marshal(protocol.Authentication{Protocol: 2, NodeID: id, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(proof)))})
	if e = conn.Write(ctx, websocket.MessageText, raw); e != nil {
		t.Fatal(e)
	}
	raw, _ = json.Marshal(protocol.Frame{Type: "telemetry", Version: protocol.Version, Data: &protocol.Telemetry{At: time.Now(), OS: "Synthetic adoption protocol fixture"}})
	if e = conn.Write(ctx, websocket.MessageText, raw); e != nil {
		t.Fatal(e)
	}
	if _, _, e = conn.Read(ctx); e != nil {
		t.Fatal(e)
	}
	return conn
}

func TestAdoptionDryRunAndReportPreserveInfrastructureBoundary(t *testing.T) {
	s, srv, _ := testServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	a := connectedAdoptionFixture(t, s, srv, "listener", ctx)
	defer a.CloseNow()
	b := connectedAdoptionFixture(t, s, srv, "client", ctx)
	defer b.CloseNow()
	discovery := func(role string) nodeops.Discovered {
		return nodeops.Discovered{Instance: nodeops.Instance{ID: "same_local_id", Name: "Synthetic service", Engine: "backhaul", Version: "0.7.2", Role: role, Hash: "config_" + role, DefinitionHash: "unit_" + role, Unit: "synthetic-" + role + ".service", Path: "/etc/synthetic-" + role + ".toml", Binary: "/opt/synthetic-backhaul"}, Fingerprint: "synthetic-pinned-binary", AuthMatch: "synthetic-opaque-shared-match", Parsed: engine.Parsed{Role: role, Transport: "tcp"}}
	}
	left, right := discovery("server"), discovery("client")
	q := JobPayload{Tunnel: "observed", Name: "Synthetic observation", Spec: sharedSpec("client", "one", 24443), ExpectedRevision: 1, Instances: map[string]string{"listener": left.ID, "client": right.ID}, Hashes: map[string]string{"listener": left.Hash, "client": right.Hash}}
	original, _ := s.sealValue("tunnel:observed", TunnelRecord{Spec: q.Spec, Instances: q.Instances, Hashes: q.Hashes})
	s.DB.Exec(ctx, "INSERT INTO tunnels(id,name,cipher,managed)VALUES('observed','Synthetic observed',$1,false)", original)
	seed := func(id string, l, r nodeops.Discovered) {
		t.Helper()
		for i, d := range []nodeops.Discovered{l, r} {
			node := []string{"listener", "client"}[i]
			raw, _ := json.Marshal(map[string]any{"instances": []nodeops.Discovered{d}})
			commandID := id + node
			result, _ := s.sealValue("result:"+commandID, protocol.Result{ID: commandID, OK: true, Data: raw})
			cipher, _ := s.sealValue("command:"+commandID, map[string]any{})
			if _, e := s.DB.Exec(ctx, "INSERT INTO commands(id,operation_id,node_id,stage,kind,cipher,result_cipher,state,expires)VALUES($1,$2,$3,'adoption_inventory','inventory',$4,$5,'completed',now()+interval '3 minutes')", commandID, id, node, cipher, result); e != nil {
				t.Fatal(e)
			}
		}
	}
	id, e := s.newJob(ctx, "dry_run", "adoption-preview", q.Tunnel, "Preview adoption", q)
	if e != nil {
		t.Fatal(e)
	}
	seed(id, left, right)
	s.processAdoptionPreview(ctx, id, q)
	var phase string
	var result []byte
	s.DB.QueryRow(ctx, "SELECT phase,result FROM operations WHERE id=$1", id).Scan(&phase, &result)
	if phase != "succeeded" {
		t.Fatalf("read-only preview failed: %s", phase)
	}
	var after []byte
	var managed bool
	s.DB.QueryRow(ctx, "SELECT cipher,managed FROM tunnels WHERE id='observed'").Scan(&after, &managed)
	var mutations int
	s.DB.QueryRow(ctx, "SELECT count(*) FROM commands WHERE kind<>'inventory'").Scan(&mutations)
	if string(after) != string(original) || managed || mutations != 0 {
		t.Fatal("dry run crossed adoption/host mutation boundary")
	}
	report := httptest.NewRecorder()
	s.adoptionReport(report, httptest.NewRequest("GET", "/api/adoption-report", nil))
	var body struct {
		Counts map[string]int `json:"counts"`
		Items  []adoptionItem `json:"items"`
	}
	json.Unmarshal(report.Body.Bytes(), &body)
	if body.Counts["adoptable"] != 2 || body.Counts["managed"] != 0 || len(body.Items) != 2 {
		t.Fatal("compatible pair classification wrong")
	}
	for _, item := range body.Items {
		if item.Status != "adoptable" {
			t.Fatal("unexpected classification")
		}
	}
	unknown := left
	unknown.ID = "unknown_version"
	unknown.Version = "not-verified"
	unknown.Parsed.Bind = "0.0.0.0:28200"
	unknown.Parsed.Routes = []engine.Route{{ID: "observed_readonly", User: engine.Endpoint{Host: "0.0.0.0", Port: 24445}, Backend: engine.Endpoint{Host: "127.0.0.1", Port: 2096}, Protocol: "tcp"}}
	unpaired := right
	unpaired.ID = "unpaired_client"
	inventory, _ := json.Marshal(map[string]any{"instances": []nodeops.Discovered{left, unknown, unpaired}})
	s.DB.Exec(ctx, "UPDATE nodes SET inventory=$1 WHERE id='listener'", inventory)
	report = httptest.NewRecorder()
	s.adoptionReport(report, httptest.NewRequest("GET", "/api/adoption-report", nil))
	json.Unmarshal(report.Body.Bytes(), &body)
	if body.Counts["adoptable"] != 2 || body.Counts["readonly"] != 1 || body.Counts["unpaired"] != 1 {
		t.Fatal("read-only/unpaired reasons were not separated")
	}
	if os.Getenv("TUNNELMANAGER_BROWSER_TESTS") == "1" {
		browserCtx, stop := context.WithCancel(ctx)
		go func() {
			timer := time.NewTicker(100 * time.Millisecond)
			defer timer.Stop()
			for {
				select {
				case <-browserCtx.Done():
					return
				case <-timer.C:
					rows, err := s.DB.Query(browserCtx, "SELECT id,cipher FROM operations WHERE kind='adoption-preview' AND phase='queued'")
					if err != nil {
						continue
					}
					type pending struct {
						id     string
						cipher []byte
					}
					items := []pending{}
					for rows.Next() {
						var p pending
						rows.Scan(&p.id, &p.cipher)
						items = append(items, p)
					}
					rows.Close()
					for _, p := range items {
						var payload JobPayload
						if s.openValue("operation:"+p.id, p.cipher, &payload) != nil {
							continue
						}
						seed(p.id, left, right)
						s.processAdoptionPreview(browserCtx, p.id, payload)
					}
				}
			}
		}()
		cmd := exec.CommandContext(ctx, "node", "web/tests/adoption.mjs")
		cmd.Dir = filepath.Join("..", "..")
		cmd.Env = append(os.Environ(), "TUNNELMANAGER_TEST_URL="+srv.URL)
		out, err := cmd.CombinedOutput()
		stop()
		if err != nil {
			t.Fatalf("adoption sample Chrome: %v\n%s", err, out)
		}
		t.Log(string(out))
		// Preview rereads replace the selected inventory. Restore the extra
		// classification cases used below; no host effect is simulated.
		s.DB.Exec(ctx, "UPDATE nodes SET inventory=$1 WHERE id='listener'", inventory)
	}
	// A completed old read receipt must not be presented as a new observation.
	expired, _ := s.newJob(ctx, "expired_dry_run", "adoption-preview", q.Tunnel, "Preview adoption", q)
	seed(expired, left, right)
	s.DB.Exec(ctx, "UPDATE commands SET expires=now()-interval '1 second' WHERE operation_id=$1", expired)
	s.processAdoptionPreview(ctx, expired, q)
	s.DB.QueryRow(ctx, "SELECT phase FROM operations WHERE id=$1", expired).Scan(&phase)
	if phase != "failed" {
		t.Fatal("expired receipt renewed read-only eligibility")
	}
	q.AdoptionEvidence = map[string]string{"listener": adoptionEvidence(left), "client": adoptionEvidence(right)}
	changed := right
	changed.DefinitionHash = "changed_unit"
	blocked, _ := s.newJob(ctx, "drift_dry_run", "adoption-preview", q.Tunnel, "Preview adoption", q)
	seed(blocked, left, changed)
	s.processAdoptionPreview(ctx, blocked, q)
	s.DB.QueryRow(ctx, "SELECT phase FROM operations WHERE id=$1", blocked).Scan(&phase)
	if phase != "failed" {
		t.Fatal("unit changed after preview accepted")
	}
	q.AdoptionEvidence = nil
	different := right
	different.AuthMatch = "different-synthetic-match"
	mismatch, _ := s.newJob(ctx, "mismatch_dry_run", "adoption-preview", q.Tunnel, "Preview adoption", q)
	seed(mismatch, left, different)
	s.processAdoption(ctx, mismatch, q)
	s.DB.QueryRow(ctx, "SELECT count(*) FROM commands WHERE kind<>'inventory'").Scan(&mutations)
	if mutations != 0 {
		t.Fatal("one side adopted before two-side authentication validation")
	}
	s.DB.QueryRow(ctx, "SELECT phase FROM operations WHERE id=$1", mismatch).Scan(&phase)
	if phase != "failed" {
		t.Fatal("shared authentication mismatch accepted")
	}
	// Successful explicit metadata adoption retains the exact adopted baseline
	// in the same transaction, including its private token in ciphertext only.
	accepted, _ := s.newJob(ctx, "accepted_baseline", "adopt", q.Tunnel, "Adopt", q)
	seed(accepted, left, right)
	for _, part := range s.changeParts(q) {
		raw, err := engine.Render(q.Spec, part.Role)
		if err != nil {
			t.Fatal(err)
		}
		commandID := accepted + part.Node + "adopt"
		data, _ := json.Marshal(map[string]string{"private_configuration": raw})
		result, _ := s.sealValue("result:"+commandID, protocol.Result{ID: commandID, OK: true, Data: data})
		cipher, _ := s.sealValue("command:"+commandID, map[string]any{})
		if _, err = s.DB.Exec(ctx, "INSERT INTO commands(id,operation_id,node_id,stage,kind,cipher,result_cipher,state,expires)VALUES($1,$2,$3,'adopt','instance.adopt',$4,$5,'completed',now()+interval '3 minutes')", commandID, accepted, part.Node, cipher, result); err != nil {
			t.Fatal(err)
		}
	}
	s.processAdoption(ctx, accepted, q)
	s.DB.QueryRow(ctx, "SELECT phase FROM operations WHERE id=$1", accepted).Scan(&phase)
	if phase != "succeeded" {
		t.Fatal("explicit adoption did not finish")
	}
	var baselineCipher []byte
	var baseline TunnelRecord
	if e = s.DB.QueryRow(ctx, "SELECT cipher FROM tunnel_versions WHERE tunnel_id=$1 AND revision=2", q.Tunnel).Scan(&baselineCipher); e != nil {
		t.Fatal("adopted baseline missing")
	}
	if s.openValue("tunnel:"+q.Tunnel, baselineCipher, &baseline) != nil || baseline.Spec.Token != q.Spec.Token {
		t.Fatal("adopted baseline cannot be restored with original authentication")
	}
	// A stale queued adoption cannot issue even a metadata ownership command.
	stale, _ := s.newJob(ctx, "stale_adopt", "adopt", q.Tunnel, "Adopt", q)
	s.processAdoption(ctx, stale, q)
	s.DB.QueryRow(ctx, "SELECT count(*) FROM commands WHERE operation_id=$1", stale).Scan(&mutations)
	if mutations != 0 {
		t.Fatal("stale queued adoption crossed revision guard")
	}
}

func TestUnsupportedAdoptionEvidenceIsNotReady(t *testing.T) {
	base := nodeops.Discovered{Instance: nodeops.Instance{Engine: "backhaul", Version: "0.7.2", Role: "server", Hash: "hash", DefinitionHash: "unit"}, Fingerprint: "binary", Parsed: engine.Parsed{Transport: "tcp"}}
	for _, tc := range []struct {
		name   string
		mutate func(*nodeops.Discovered)
		reason string
	}{
		{"version", func(d *nodeops.Discovered) { d.Version = "unknown" }, "unverified_version"},
		{"option", func(d *nodeops.Discovered) { d.Reason = "unsupported engine option: custom" }, "unsupported_configuration"},
		{"transport", func(d *nodeops.Discovered) { d.Parsed.Transport = "udp" }, "unsupported_configuration"},
		{"wrong option side", func(d *nodeops.Discovered) { d.Parsed.Options = map[string]any{"connection_pool": float64(8)} }, "unsupported_configuration"},
		{"unit", func(d *nodeops.Discovered) { d.DefinitionHash = "" }, "missing_binary_or_unit_evidence"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := base
			tc.mutate(&d)
			if supportReason(d) != tc.reason {
				t.Fatal("unsupported service called ready")
			}
		})
	}
}
