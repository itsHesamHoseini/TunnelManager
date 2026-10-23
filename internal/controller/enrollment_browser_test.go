package controller

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestLiveEnrollmentChrome(t *testing.T) {
	if os.Getenv("TUNNELMANAGER_BROWSER_TESTS") != "1" {
		t.Skip("actual Chrome opt-in required")
	}
	_, srv, _ := testServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "node", "web/tests/enrollment.mjs")
	cmd.Dir = filepath.Join("..", "..")
	cmd.Env = append(os.Environ(), "TUNNELMANAGER_TEST_URL="+srv.URL)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sample enrollment Chrome: %v\n%s", err, out)
	}
	t.Log(string(out))
}
