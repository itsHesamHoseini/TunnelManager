package nodeops

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/itsHesamHoseini/TunnelManager/internal/engine"
)

func TestUnsupportedOwnedInstanceNeverBecomesMutable(t *testing.T) {
	r := &Runtime{StateDir: t.TempDir(), ConfigDir: t.TempDir()}
	p := filepath.Join(t.TempDir(), "legacy.toml")
	old := []byte("[client]\nremote_addr='example.test:28100'\n")
	if e := os.WriteFile(p, old, 0600); e != nil {
		t.Fatal(e)
	}
	v := Instance{ID: "old_instance", Engine: "unknown_engine", Managed: true, Path: p, Hash: engine.Digest(old), Unit: "preserve-unknown.service"}
	if e := r.save(v); e != nil {
		t.Fatal(e)
	}
	if _, e := r.load(v.ID); e == nil {
		t.Fatal("unsupported instance still mutable")
	}
	if _, _, e := registryRaw(r, v.ID); e == nil {
		t.Fatal("unsupported configuration still managed")
	}
	after, _ := os.ReadFile(p)
	if string(after) != string(old) {
		t.Fatal("unsupported host file changed")
	}
	if _, e := os.Stat(r.file("instances", v.ID+".json")); e != nil {
		t.Fatal("legacy ownership record deleted instead of preserved")
	}
}

func TestUnknownCertificateConsumerPreservesSharedFiles(t *testing.T) {
	r := &Runtime{StateDir: t.TempDir(), ConfigDir: t.TempDir()}
	p := filepath.Join(t.TempDir(), "unknown.toml")
	raw := "[client]\ntrust='" + filepath.ToSlash(filepath.Join(r.ConfigDir, "certificates", "cert1", "old-format.crt")) + "'\n"
	if e := os.WriteFile(p, []byte(raw), 0600); e != nil {
		t.Fatal(e)
	}
	r.save(Instance{ID: "unknown_consumer", Engine: "unknown_engine", Managed: true, Path: p})
	if _, e := r.certificateMembers(context.Background(), Certificate{ID: "cert1"}, nil); e == nil || e.Error() != "external_certificate_consumer_preserved_use_separate_certificate" {
		t.Fatal("external consumer was not protected", e)
	}
	after, _ := os.ReadFile(p)
	if string(after) != raw {
		t.Fatal("external consumer file changed")
	}
}

func TestAgentUpdatePreconditionPreservesPendingRollback(t *testing.T) {
	r := &Runtime{StateDir: t.TempDir()}
	for _, phase := range []string{"prepared", "activating", "awaiting_confirmation", "needs_review"} {
		if e := writeJSON(r.file("changes", "pending.json"), map[string]string{"Phase": phase}); e != nil {
			t.Fatal(e)
		}
		if r.PendingRollback() == nil {
			t.Fatal("agent update could replace a pending rollback executable", phase)
		}
	}
	for _, phase := range []string{"confirmed", "reverted", "released"} {
		writeJSON(r.file("changes", "pending.json"), map[string]string{"Phase": phase})
		if e := r.PendingRollback(); e != nil {
			t.Fatal("completed local journal incorrectly blocks update", e)
		}
	}
}
