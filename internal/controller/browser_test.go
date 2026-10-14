package controller

import (
	"github.com/itsHesamHoseini/TunnelManager/internal/ui"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRealBrowser(t *testing.T) {
	if os.Getenv("TUNNELMANAGER_BROWSER_TESTS") != "1" {
		t.Skip("browser tests opt-in")
	}
	s, srv, _ := testServer(t)
	s.Config.Static = ui.Handler()
	cmd := exec.Command("node", "web/tests/live.mjs")
	cmd.Dir = filepath.Join("..", "..")
	cmd.Env = append(os.Environ(), "TUNNELMANAGER_TEST_URL="+srv.URL)
	out, e := cmd.CombinedOutput()
	if e != nil {
		t.Fatalf("browser failed: %v\n%s", e, out)
	}
	t.Log(string(out))
}
