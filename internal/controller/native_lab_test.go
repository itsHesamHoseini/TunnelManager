//go:build linux && nativelab

package controller

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/itsHesamHoseini/TunnelManager/internal/secure"
	"math/big"
	"net"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNativeControllerBrowserWorkflow(t *testing.T) {
	if os.Getenv("CI") != "true" || os.Getenv("TUNNELMANAGER_NATIVE_LAB") != "1" {
		t.Skip("isolated CI only")
	}
	s, _, _ := testServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 18*time.Minute)
	defer cancel()
	private, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	cert := x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "controller.example.com"}, DNSNames: []string{"controller.example.com"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, &cert, &cert, &private.PublicKey, private)
	if e != nil {
		t.Fatal(e)
	}
	encoded, _ := x509.MarshalPKCS8PrivateKey(private)
	public := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	pair, _ := tls.X509KeyPair(public, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}))
	srv := httptest.NewUnstartedServer(s.Handler())
	srv.Listener.Close()
	srv.Listener, e = net.Listen("tcp", "0.0.0.0:0")
	if e != nil {
		t.Fatal(e)
	}
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()
	port := srv.Listener.Addr().(*net.TCPAddr).Port
	s.Config.Origin = fmt.Sprintf("https://127.0.0.1:%d", port)
	client := srv.Client()
	client.Jar, _ = cookiejar.New(nil)
	srv.URL = s.Config.Origin
	codes := enrollMFA(t, srv, client)
	go s.Operations(ctx)
	work, e := os.MkdirTemp("", "tm-native-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(work)
	os.Chmod(work, 0700)
	ca := filepath.Join(work, "controller.crt")
	os.WriteFile(ca, public, 0600)
	binary := filepath.Join(work, "tunnelmanager")
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, "./cmd/tunnelmanager")
	build.Dir = filepath.Join("..", "..")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if b, e := build.CombinedOutput(); e != nil {
		t.Fatalf("CLI build failed: %v %s", e, b)
	}
	run := func(args ...string) []byte {
		t.Helper()
		cmd := exec.CommandContext(ctx, "docker", args...)
		b, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatalf("lab %s failed: %v %s", args[0], e, b)
		}
		return b
	}
	suffix := fmt.Sprint(time.Now().UnixNano())
	network := "tm-flow-" + suffix
	run("network", "create", network)
	t.Cleanup(func() { exec.Command("docker", "network", "rm", network).Run() })
	nodes := []string{"tm-listener-" + suffix, "tm-dialer-" + suffix}
	ips := []string{}
	ids := []string{}
	for i, node := range nodes {
		run("run", "-d", "--name", node, "--network", network, "--add-host", "controller.example.com:host-gateway", "--privileged", "--cgroupns=host", "--tmpfs", "/run", "--tmpfs", "/run/lock", "--tmpfs", "/tmp", "-v", "/sys/fs/cgroup:/sys/fs/cgroup:rw", "tunnelmanager-native-lab")
		n := node
		t.Cleanup(func() { exec.Command("docker", "rm", "-f", n).Run() })
		run("exec", node, "mkdir", "-p", "/lab/public")
		run("cp", binary, node+":/lab/tunnelmanager")
		run("cp", ca, node+":/lab/controller.crt")
		run("exec", node, "chmod", "700", "/lab/tunnelmanager")
		for attempt := 0; attempt < 30; attempt++ {
			b, _ := exec.CommandContext(ctx, "docker", "exec", node, "systemctl", "is-system-running").Output()
			if strings.Contains(string(b), "running") || strings.Contains(string(b), "degraded") {
				break
			}
			time.Sleep(time.Second)
		}
		token, e := s.CreateEnrollment(ctx, []string{"Synthetic Linux listener", "Synthetic Linux dialer"}[i], []string{"iran", "foreign"}[i], false)
		if e != nil {
			t.Fatal(e)
		}
		cmd := exec.CommandContext(ctx, "docker", "exec", "-i", node, "/lab/tunnelmanager", "setup", "--mode", "node", "--yes", "--controller", fmt.Sprintf("https://controller.example.com:%d", port), "--ca", "/lab/controller.crt", "--token-stdin")
		cmd.Stdin = strings.NewReader(token + "\n")
		if out, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("native enrollment failed (token suppressed): %v\n%s", e, out)
		}
		var id string
		var pub []byte
		name := []string{"Synthetic Linux listener", "Synthetic Linux dialer"}[i]
		if s.DB.QueryRow(ctx, "SELECT id,pubkey FROM nodes WHERE name=$1", name).Scan(&id, &pub) != nil {
			t.Fatal("enrollment absent")
		}
		status, _ := request(t, client, srv.URL+"/api/nodes/"+id+"/approve", "POST", map[string]any{"fingerprint": secure.Fingerprint(pub)})
		if status != 200 {
			t.Fatal("explicit identity approval failed")
		}
		ids = append(ids, id)
		ips = append(ips, strings.TrimSpace(string(run("inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", node))))
		cmd = exec.CommandContext(ctx, "docker", "exec", "-i", node, "sh", "-c", "umask 077; cat > /lab/public/probe")
		cmd.Stdin = strings.NewReader("synthetic-native-response")
		if e = cmd.Run(); e != nil {
			t.Fatal(e)
		}
		run("exec", node, "systemd-run", "--unit=lab-backend", "python3", "-m", "http.server", "29096", "--bind", "127.0.0.1", "--directory", "/lab/public")
	}
	for _, id := range ids {
		ready := false
		for attempt := 0; attempt < 45; attempt++ {
			var version int
			var seen *time.Time
			s.DB.QueryRow(ctx, "SELECT protocol,seen FROM nodes WHERE id=$1", id).Scan(&version, &seen)
			if version == 2 && seen != nil {
				ready = true
				break
			}
			time.Sleep(time.Second)
		}
		if !ready {
			t.Fatal("approved native agent did not send observations")
		}
	}
	wait := func(id string) {
		t.Helper()
		for attempt := 0; attempt < 100; attempt++ {
			var phase, code string
			s.DB.QueryRow(ctx, "SELECT phase,error FROM operations WHERE id=$1", id).Scan(&phase, &code)
			if phase == "succeeded" {
				return
			}
			if phase == "failed" {
				t.Fatal("native operation: " + code)
			}
			time.Sleep(time.Second)
		}
		t.Fatal("native operation timeout")
	}
	for _, node := range ids {
		for _, engine := range []string{"rathole", "backhaul"} {
			version := map[string]string{"rathole": "0.5.0", "backhaul": "0.7.2"}[engine]
			body, _ := json.Marshal(map[string]string{"Engine": engine, "Version": version})
			id, e := s.newJob(ctx, "install_"+node+"_"+engine, "node", node, "Install", JobPayload{Node: node, Kind: "engine.install", Payload: body})
			if e != nil {
				t.Fatal(e)
			}
			wait(id)
		}
	}
	fixture := map[string]any{"url": srv.URL, "recovery": codes[0], "listener": ids[0], "dialer": ids[1], "listener_ip": ips[0], "dialer_ip": ips[1]}
	raw, _ := json.Marshal(fixture)
	fixturePath := filepath.Join(work, "browser.json")
	os.WriteFile(fixturePath, raw, 0600)
	command := exec.CommandContext(ctx, "node", "web/tests/native.mjs")
	command.Dir = filepath.Join("..", "..")
	command.Env = append(os.Environ(), "TUNNELMANAGER_NATIVE_FIXTURE="+fixturePath)
	out, e := command.CombinedOutput()
	if e != nil {
		t.Fatalf("native browser workflow failed: %v\n%s", e, out)
	}
	t.Log(string(out))
	// Stop both control agents after confirmation. Actual HTTP data plane persists.
	for _, node := range nodes {
		run("exec", node, "systemctl", "stop", "tunnelmanager-agent")
	}
	run("exec", nodes[1], "python3", "-c", "import urllib.request; assert b'synthetic-native-response' in urllib.request.urlopen('http://"+ips[0]+":24443/probe',timeout=5).read()")
	t.Log("Real controller/PostgreSQL/browser -> signed outbound TLS agents -> two Linux systemd peers and both engines passed; data plane works with both agents stopped")
}
