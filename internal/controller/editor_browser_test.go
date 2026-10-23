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

func TestSimpleEditorChrome(t *testing.T) {
	if os.Getenv("TUNNELMANAGER_BROWSER_TESTS") != "1" {
		t.Skip("real Chrome opt-in required")
	}
	s, srv, _ := testServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	for i, node := range []string{"listener", "client"} {
		name := []string{"نمونه ایران", "نمونه خارج"}[i]
		role := []string{"iran", "foreign"}[i]
		if _, e := s.DB.Exec(ctx, "INSERT INTO nodes(id,name,role,pubkey,approved,seen,telemetry)VALUES($1,$2,$3,$4,true,now(),'{\"cpu_percent\":20}')", node, name, role, make([]byte, 32)); e != nil {
			t.Fatal(e)
		}
	}
	spec := sharedSpec("client", "mapping_stable", 24443)
	spec.Routes[0].Name = "ورودی اصلی"
	cipher, _ := s.sealValue("tunnel:sample_editor", TunnelRecord{Spec: spec, Instances: map[string]string{"listener": "sample_s", "client": "sample_c"}})
	s.DB.Exec(ctx, "INSERT INTO tunnels(id,name,cipher,managed)VALUES('sample_editor','نمونه تونل قابل ویرایش',$1,true)", cipher)
	payload, _ := json.Marshal(CertificateRequest{Name: "نمونه گواهی", Domain: "transport.example.com", Method: "self-signed", Days: 3})
	job, _ := s.newJob(ctx, "editor_sample_certificate", "certificate", "sample_cert", "Sample", JobPayload{Kind: "issue", Certificate: "sample_cert", Payload: payload})
	s.processJob(ctx, job)
	// UI-only fixture: render a real durable plan without claiming agent effects.
	// Never process applying/confirming here. Native CI exercises those separately.
	go func() {
		timer := time.NewTicker(100 * time.Millisecond)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				rows, e := s.DB.Query(ctx, "SELECT id,cipher FROM operations WHERE kind='plan' AND phase='queued'")
				if e != nil {
					continue
				}
				type draft struct {
					id     string
					cipher []byte
				}
				pending := []draft{}
				for rows.Next() {
					var d draft
					rows.Scan(&d.id, &d.cipher)
					pending = append(pending, d)
				}
				rows.Close()
				for _, d := range pending {
					var q JobPayload
					if s.openValue("operation:"+d.id, d.cipher, &q) != nil {
						continue
					}
					previews := map[string]any{}
					for _, part := range q.Parts {
						current, _ := engine.Render(spec, part.Role)
						proposed, _ := engine.Render(part.Spec, part.Role)
						previews[part.Node+":"+part.Instance] = map[string]any{"current": engine.Redact(current), "configuration": engine.Redact(proposed)}
					}
					s.phase(ctx, d.id, "ready", map[string]any{"sample": true, "previews": previews, "affected_tunnels": publicAffected(q), "changes": q.Changes}, nil)
				}
			}
		}
	}()
	cmd := exec.CommandContext(ctx, "node", "web/tests/simple-editor.mjs")
	cmd.Dir = filepath.Join("..", "..")
	cmd.Env = append(os.Environ(), "TUNNELMANAGER_TEST_URL="+srv.URL)
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("sample editor Chrome: %v\n%s", e, out)
	} else {
		t.Log(string(out))
	}
	var commands int
	s.DB.QueryRow(ctx, "SELECT count(*) FROM commands").Scan(&commands)
	if commands != 0 {
		t.Fatal("sample UI test queued a real node command")
	}
}
