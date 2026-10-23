package controller

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// This is an actual cross-compiled Go ELF, used only to verify distribution
// bytes/metadata. Executing setup/systemd remains the separate native test.
func bootstrapFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	source := filepath.Join(dir, "main.go")
	if err := os.WriteFile(source, []byte("package main\nfunc main() {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "node")
	cmd := exec.Command("go", "build", "-o", binary, source)
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "GOOS=") && !strings.HasPrefix(value, "GOARCH=") && !strings.HasPrefix(value, "CGO_ENABLED=") {
			cmd.Env = append(cmd.Env, value)
		}
	}
	cmd.Env = append(cmd.Env, "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile fixture: %v %s", err, out)
	}
	return binary
}

func bootstrapServer(t *testing.T, path string) *Server {
	s, _, _ := testServer(t)
	s.Config.Origin = "https://controller.example.com:9443"
	s.bootstrapPath = path
	return s
}
func bootstrapGet(t *testing.T, s *Server, path, arch, ip string) *httptest.ResponseRecorder {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.RemoteAddr = ip + ":41234"
		r.SetPathValue("arch", arch)
		if arch == "" {
			s.bootstrapScript(w, r)
		} else {
			s.bootstrapDownload(w, r)
		}
	}))
	defer server.Close()
	response, err := http.Get(server.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	w.Code = response.StatusCode
	w.HeaderMap = response.Header
	w.Body.Write(body)
	return w
}

func TestBootstrapPinnedBytesAndGuards(t *testing.T) {
	path := bootstrapFixture(t)
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(contents)
	s := bootstrapServer(t, path)
	meta, err := s.bootstrapArtifact()
	if err != nil || meta.Arch != "amd64" || meta.Hash != hex.EncodeToString(digest[:]) || meta.Size != int64(len(contents)) {
		t.Fatalf("metadata mismatch: %v", err)
	}
	script := bootstrapGet(t, s, "/bootstrap/node-install.sh", "", "192.0.2.1")
	if script.Code != 200 || !strings.Contains(script.Body.String(), meta.Hash) || !strings.Contains(script.Body.String(), "--token-stdin") || strings.Contains(script.Body.String(), "@HASH@") || strings.Contains(script.Body.String(), "--insecure") {
		t.Fatal("bootstrap script not pinned or unsafe")
	}
	if script.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("script cached")
	}
	good := bootstrapGet(t, s, "/bootstrap/node/amd64?path=/etc/private", "amd64", "192.0.2.2")
	if good.Code != 200 || !bytes.Equal(good.Body.Bytes(), contents) || good.Header().Get("Content-Type") != "application/octet-stream" {
		t.Fatal("download did not serve exact pinned program bytes")
	}
	wrong := bootstrapGet(t, s, "/bootstrap/node/arm64", "arm64", "192.0.2.3")
	if wrong.Code != 404 {
		t.Fatal("wrong architecture accepted")
	}
	s.bootstrapSlots <- struct{}{}
	busy := bootstrapGet(t, s, "/bootstrap/node/amd64", "amd64", "192.0.2.4")
	<-s.bootstrapSlots
	if busy.Code != 429 || bytes.Equal(busy.Body.Bytes(), contents) {
		t.Fatal("concurrent download not bounded")
	}
	for i := 0; i < 2; i++ {
		if bootstrapGet(t, s, "/bootstrap/node/amd64", "amd64", "192.0.2.5").Code != 200 {
			t.Fatal("rate fixture unavailable")
		}
	}
	if bootstrapGet(t, s, "/bootstrap/node/amd64", "amd64", "192.0.2.5").Code != 429 {
		t.Fatal("download rate unbounded")
	}
	// Keep a valid Go ELF, but change its digest after the first metadata read.
	if err := os.WriteFile(path, append(contents, byte(0)), 0600); err != nil {
		t.Fatal(err)
	}
	if bootstrapGet(t, s, "/bootstrap/node/amd64", "amd64", "192.0.2.6").Code != 503 {
		t.Fatal("changed artifact escaped pinned digest")
	}
}

func TestBootstrapRejectsInvalidFilesAndOrigins(t *testing.T) {
	dir := t.TempDir()
	for name, data := range map[string][]byte{"empty": nil, "private": bytes.Repeat([]byte("private-runtime-data"), 20), "truncated": []byte("\x7fELF")} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		if f, _, err := openNodeArtifact(path); err == nil {
			f.Close()
			t.Fatal("invalid artifact accepted: " + name)
		}
	}
	if f, _, err := openNodeArtifact(dir); err == nil {
		f.Close()
		t.Fatal("directory accepted")
	}
	large := filepath.Join(dir, "oversized")
	f, err := os.Create(large)
	if err != nil {
		t.Fatal(err)
	}
	err = f.Truncate(nodeArtifactLimit + 1)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if f, _, err := openNodeArtifact(large); err == nil {
		f.Close()
		t.Fatal("oversized artifact accepted")
	}
	s := bootstrapServer(t, filepath.Join(dir, "missing"))
	if bootstrapGet(t, s, "/bootstrap/node-install.sh", "", "192.0.2.1").Code != 503 {
		t.Fatal("missing artifact advertised")
	}
	for _, origin := range []string{"http://controller.example.com", "https://user" + ":password@" + "controller.example.com", "https://controller.example.com/?secret=value", "https://controller.example.com/other", "https://controller.example.com/#fragment"} {
		s.Config.Origin = origin
		if _, err := s.bootstrapOrigin(); err == nil {
			t.Fatal("invalid origin accepted")
		}
	}
	if got := shellLiteral("https://example.com/a'b"); got != "'https://example.com/a'\"'\"'b'" {
		t.Fatal("shell literal not escaped")
	}
	// No node name, token or owner command is interpolated into shell source.
	s = bootstrapServer(t, bootstrapFixture(t))
	command, err := s.bootstrapCommand()
	if err != nil || strings.Contains(command, "--token") || strings.Contains(command, "curl -k") || !strings.Contains(command, "--proto '=https'") {
		t.Fatal("unsafe command")
	}
}
