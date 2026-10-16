package nodeops

import (
	"context"
	"encoding/json"
	"github.com/itsHesamHoseini/TunnelManager/internal/engine"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPreparedRollbackDoesNotTouchRunningUnit(t *testing.T) {
	r := &Runtime{StateDir: t.TempDir()}
	j := Journal{Change: Change{ID: "change1", Instance: "instance1", Deadline: time.Now().Add(time.Minute)}, Candidate: Instance{ID: "instance1", Unit: "never-touch.service"}, Phase: "prepared"}
	if e := writeJSON(r.file("changes", "change1.json"), j); e != nil {
		t.Fatal(e)
	}
	if e := r.pending("instance1", ""); e == nil {
		t.Fatal("pending mutation not locked")
	}
	if e := r.rollback(context.Background(), "change1"); e != nil {
		t.Fatal(e)
	}
	if e := r.pending("instance1", ""); e != nil {
		t.Fatal(e)
	}
}
func TestDriftAndBoundedLogRedaction(t *testing.T) {
	r := &Runtime{StateDir: t.TempDir()}
	p := filepath.Join(t.TempDir(), "config.toml")
	os.WriteFile(p, []byte("old"), 0600)
	v := Instance{ID: "instance1", Path: p, Managed: true, Hash: engine.Digest([]byte("old"))}
	r.save(v)
	if _, _, e := registryRaw(r, v.ID); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(p, []byte("manual"), 0600)
	if _, _, e := registryRaw(r, v.ID); e == nil {
		t.Fatal("manual overwrite accepted")
	}
	out := redactLog("token=synthetic password:synthetic https" + "://" + "user:pass@example.com/path 00000000-0000-4000-8000-000000000000")
	if strings.Contains(out, "synthetic") || strings.Contains(out, "user:pass") || strings.Contains(out, "00000000") {
		t.Fatal("log credential leak")
	}
}
func TestTypedPayloadRejectsShellAndUnknownFields(t *testing.T) {
	var q struct{ ID string }
	if decode([]byte(`{"ID":"a","shell":"id"}`), &q) == nil {
		t.Fatal("unknown field accepted")
	}
	if decode([]byte(`{"ID":"a"} {"ID":"b"}`), &q) == nil {
		t.Fatal("trailing command accepted")
	}
	b, _ := json.Marshal(map[string]string{"ID": "normal"})
	if e := decode(b, &q); e != nil {
		t.Fatal(e)
	}
}

func TestCertificateCompensationRefusesNewerDeploymentAndManualFiles(t *testing.T) {
	r := &Runtime{StateDir: t.TempDir(), ConfigDir: t.TempDir()}
	j := certTransaction{ID: "cert_job1", Certificate: "cert1", Phase: "applying", Old: map[string][]byte{"cert.pem": []byte("old")}, New: map[string][]byte{"cert.pem": []byte("new")}}
	writeJSON(r.file("certificate-transactions", j.ID+".json"), j)
	r.writeCertFiles("cert1", map[string][]byte{"cert.pem": []byte("manual")})
	if e := r.revertCert(context.Background(), j.ID, true); e == nil {
		t.Fatal("manual certificate overwritten")
	}
	r.writeCertFiles("cert1", j.New)
	writeJSON(r.file("certificate-state", "cert1.json"), certState{ID: "cert_later", Hash: filesHash(j.New)})
	if e := r.revertCert(context.Background(), j.ID, true); e == nil {
		t.Fatal("newer certificate deployment overwritten")
	}
	files, _ := r.certFiles("cert1")
	if string(files["cert.pem"]) != "new" {
		t.Fatal("guard mutated certificate")
	}
	if filesHash(j.New) == filesHash(map[string][]byte{"cert.pem": []byte("new"), "key.pem": []byte("different")}) {
		t.Fatal("private key drift not hashed")
	}
}
