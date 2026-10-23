//go:build linux && nativelab

package nodeops

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/itsHesamHoseini/TunnelManager/internal/engine"
	"github.com/itsHesamHoseini/TunnelManager/internal/protocol"
)

// Runs only in disposable CI containers. The actual production Runtime executes
// commands; this adapter transports fixtures without exposing them in logs.
func TestMain(m *testing.M) {
	_, inside := os.Stat("/lab/inside")
	if inside == nil && len(os.Args) > 1 {
		r := &Runtime{ConfigDir: "/etc/tunnelmanager-agent", StateDir: "/var/lib/tunnelmanager-agent"}
		switch os.Args[1] {
		case "local-rollback":
			var id string
			for i, a := range os.Args {
				if a == "--id" && i+1 < len(os.Args) {
					id = os.Args[i+1]
				}
			}
			if e := r.Rollback(context.Background(), id); e != nil {
				os.Exit(1)
			}
			os.Exit(0)
		case "backend", "backend-alt":
			port := "29096"
			if os.Args[1] == "backend-alt" {
				port = "29097"
			}
			http.ListenAndServe("0.0.0.0:"+port, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "lab-response") }))
			os.Exit(1)
		case "execute":
			b, e := os.ReadFile("/lab/request.json")
			if e != nil {
				os.Exit(2)
			}
			var c protocol.Command
			if json.Unmarshal(b, &c) != nil {
				os.Exit(2)
			}
			v := r.Execute(context.Background(), c)
			if writeJSON("/lab/result.json", v) != nil {
				os.Exit(2)
			}
			os.Exit(0)
		}
	}
	os.Exit(m.Run())
}
func TestNativeBackhaul(t *testing.T) {
	runNativeBackhaul(t, false)
}
func TestNativeOrdinaryEditFailureMatrix(t *testing.T) {
	runNativeBackhaul(t, true)
}
func runNativeBackhaul(t *testing.T, matrix bool) {
	if os.Getenv("CI") != "true" || os.Getenv("TUNNELMANAGER_NATIVE_LAB") != "1" {
		t.Skip("requires isolated CI systemd containers")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	suffix := fmt.Sprint(time.Now().UnixNano())
	network := "tm-lab-" + suffix
	run := func(args ...string) []byte {
		t.Helper()
		cmd := exec.CommandContext(ctx, "docker", args...)
		b, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatalf("disposable lab command %s failed: %v\n%s", args[0], e, b)
		}
		return b
	}
	run("network", "create", network)
	t.Cleanup(func() { exec.Command("docker", "network", "rm", network).Run() })
	self, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	nodes := []string{"tm-a-" + suffix, "tm-b-" + suffix}
	ips := map[string]string{}
	for _, node := range nodes {
		run("run", "-d", "--name", node, "--network", network, "--privileged", "--cgroupns=host", "--tmpfs", "/run", "--tmpfs", "/run/lock", "--tmpfs", "/tmp", "-v", "/sys/fs/cgroup:/sys/fs/cgroup:rw", "-e", "TUNNELMANAGER_LAB_INSIDE=1", "tunnelmanager-native-lab")
		n := node
		t.Cleanup(func() { exec.Command("docker", "rm", "-f", n).Run() })
		run("exec", node, "mkdir", "-p", "/lab", "/etc/tunnelmanager-agent/instances", "/etc/tunnelmanager-agent/certificates", "/var/lib/tunnelmanager-agent", "/opt/tunnelmanager/engines")
		run("exec", node, "touch", "/lab/inside")
		run("cp", self, node+":/lab/nodeops.test")
		run("exec", node, "chmod", "700", "/lab/nodeops.test")
		for i := 0; i < 30; i++ {
			cmd := exec.CommandContext(ctx, "docker", "exec", node, "systemctl", "is-system-running")
			b, _ := cmd.Output()
			if strings.Contains(string(b), "running") || strings.Contains(string(b), "degraded") {
				break
			}
			time.Sleep(time.Second)
		}
		ips[node] = strings.TrimSpace(string(run("inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", node)))
		run("exec", node, "systemd-run", "--unit=lab-backend", "/lab/nodeops.test", "backend")
		if matrix {
			run("exec", node, "systemd-run", "--unit=lab-backend-alt", "/lab/nodeops.test", "backend-alt")
		}
	}
	sequence := 0
	call := func(node, kind string, payload any) protocol.Result {
		t.Helper()
		sequence++
		b, _ := json.Marshal(payload)
		c := protocol.Command{ID: fmt.Sprintf("command_%d", sequence), Kind: kind, Payload: b, Expires: time.Now().Add(3 * time.Minute)}
		b, _ = json.Marshal(c)
		cmd := exec.CommandContext(ctx, "docker", "exec", "-i", node, "sh", "-c", "umask 077; cat > /lab/request.json")
		cmd.Stdin = bytes.NewReader(b)
		if out, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("lab request: %v %s", e, out)
		}
		run("exec", node, "/lab/nodeops.test", "execute")
		var result protocol.Result
		if e := json.Unmarshal(run("exec", node, "cat", "/lab/result.json"), &result); e != nil {
			t.Fatal(e)
		}
		return result
	}
	require := func(node, kind string, p any) protocol.Result {
		t.Helper()
		v := call(node, kind, p)
		if !v.OK {
			t.Fatalf("%s: %s", kind, v.Code)
		}
		return v
	}
	a, b := nodes[0], nodes[1]
	checkHTTP := func(port int) {
		t.Helper()
		for attempt := 0; attempt < 20; attempt++ {
			v := require(b, "diagnostic", Diagnostic{Kind: "http", Endpoint: engine.Endpoint{Host: ips[a], Port: port}, Path: "/", Expected: "lab-response"})
			var result map[string]any
			json.Unmarshal(v.Data, &result)
			if result["status"] == "passed" {
				return
			}
			time.Sleep(time.Second)
		}
		t.Fatal("actual tunneled HTTP response unavailable")
	}
	for index, name := range []string{"backhaul"} {
		t.Run(name, func(t *testing.T) {
			version := "0.7.2"
			for _, node := range nodes {
				require(node, "engine.install", map[string]string{"Engine": name, "Version": version})
			}
			spec := engine.Spec{Engine: name, Version: version, Transport: "tcp", Listener: "a", Dialer: "b", TransportBind: engine.Endpoint{Host: "0.0.0.0", Port: 28001 + index}, TransportRemote: engine.Endpoint{Host: ips[a], Port: 28001 + index}, Token: "synthetic-lab-only-token", Routes: []engine.Route{{ID: "first", Name: "First route", User: engine.Endpoint{Host: "0.0.0.0", Port: 24443 + index*10}, Backend: engine.Endpoint{Host: "127.0.0.1", Port: 29096}, Protocol: "tcp"}, {ID: "second", Name: "Shared route", User: engine.Endpoint{Host: "0.0.0.0", Port: 24444 + index*10}, Backend: engine.Endpoint{Host: "127.0.0.1", Port: 29096}, Protocol: "tcp"}}}
			hashes := map[string]string{}
			instance := map[string]string{a: name + "_s", b: name + "_c"}
			change := func(id string, proposed engine.Spec, confirm bool) {
				t.Helper()
				for _, node := range nodes {
					role := "server"
					if node == b {
						role = "client"
					}
					require(node, "change.prepare", Change{ID: id, Instance: instance[node], Name: name, Role: role, ExpectedHash: hashes[node], Spec: proposed, Deadline: time.Now().Add(5 * time.Minute)})
				}
				deadline := time.Now().Add(90 * time.Second)
				for _, node := range nodes {
					v := require(node, "change.activate", map[string]any{"ID": id, "Deadline": deadline})
					var out struct {
						Instance Instance `json:"instance"`
					}
					json.Unmarshal(v.Data, &out)
					if confirm {
						hashes[node] = out.Instance.Hash
					}
				}
				checkHTTP(proposed.Routes[0].User.Port)
				if confirm {
					for _, node := range nodes {
						require(node, "change.confirm", map[string]any{"ID": id})
					}
					for _, node := range nodes {
						require(node, "change.confirm", map[string]any{"ID": id, "Commit": true})
					}
				}
			}
			change(name+"_create", spec, true)
			checkHTTP(spec.Routes[1].User.Port)
			if matrix {
				// Fixed synthetic certificate setup is test infrastructure only.
				// No private bytes enter output, requests or artifact screenshots.
				run("exec", a, "mkdir", "-p", "/etc/tunnelmanager-agent/certificates/matrix")
				run("exec", a, "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=matrix.example.com", "-keyout", "/etc/tunnelmanager-agent/certificates/matrix/key.pem", "-out", "/etc/tunnelmanager-agent/certificates/matrix/cert.pem")
				run("exec", a, "chmod", "600", "/etc/tunnelmanager-agent/certificates/matrix/key.pem")
				publicCertificate := filepath.Join(t.TempDir(), "matrix-cert.pem")
				run("cp", a+":/etc/tunnelmanager-agent/certificates/matrix/cert.pem", publicCertificate)
				run("exec", b, "mkdir", "-p", "/etc/tunnelmanager-agent/certificates/matrix")
				run("cp", publicCertificate, b+":/etc/tunnelmanager-agent/certificates/matrix/cert.pem")
				for _, edit := range []string{"user_port", "destination", "token", "transport"} {
					proposed := spec
					proposed.Routes = append([]engine.Route{}, spec.Routes...)
					switch edit {
					case "user_port":
						proposed.Routes[0].User.Port += 100
					case "destination":
						proposed.Routes[0].Backend = engine.Endpoint{Host: "localhost", Port: 29097}
					case "token":
						proposed.Token = "synthetic-matrix-rotated-auth"
					case "transport":
						proposed.Transport = "wss"
						proposed.Certificate = "matrix"
						proposed.AllowUnverifiedTLS = true
					}
					protected := func() string {
						value := ""
						for _, node := range nodes {
							value += string(run("exec", node, "sha256sum", "/etc/tunnelmanager-agent/instances/"+instance[node]+".toml")) + string(run("exec", node, "systemctl", "show", "tunnelmanager-instance-"+instance[node]+".service", "-p", "MainPID"))
						}
						return value
					}
					before := protected()
					blocked := call(b, "change.preflight", Change{ID: "matrix_" + edit + "_blocked", Instance: instance[b], Role: "client", ExpectedHash: "stale-synthetic-hash", Spec: proposed})
					if blocked.OK || blocked.Code != "config_revision_conflict" || protected() != before {
						t.Fatal("preflight rejection changed real configuration or process")
					}
					change("matrix_"+edit+"_apply", proposed, true)
					change("matrix_"+edit+"_manual_restore", spec, true)
					checkHTTP(spec.Routes[0].User.Port)
					id := "matrix_" + edit + "_partial"
					for _, node := range nodes {
						role := "server"
						if node == b {
							role = "client"
						}
						require(node, "change.prepare", Change{ID: id, Instance: instance[node], Name: name, Role: role, ExpectedHash: hashes[node], Spec: proposed, Deadline: time.Now().Add(5 * time.Minute)})
						run("exec", node, "test", "-s", "/var/lib/tunnelmanager-agent/backups/"+id+".toml")
					}
					require(a, "change.activate", map[string]any{"ID": id, "Deadline": time.Now().Add(90 * time.Second)})
					failed := call(b, "change.activate", map[string]any{"ID": id, "Deadline": time.Now().Add(-time.Second)})
					if failed.OK {
						t.Fatal("injected second-peer activation failure was accepted")
					}
					// Both executor processes are absent. The actual server timer must
					// restore locally, without a controller or a polling rollback call.
					time.Sleep(95 * time.Second)
					raw := run("exec", a, "cat", "/var/lib/tunnelmanager-agent/changes/"+id+".json")
					var journal Journal
					if json.Unmarshal(raw, &journal) != nil || journal.Phase != "reverted" {
						t.Fatal("90-second local timer did not restore partial edit")
					}
					require(b, "change.rollback", map[string]string{"ID": id})
					for _, node := range nodes {
						current := run("exec", node, "cat", "/etc/tunnelmanager-agent/instances/"+instance[node]+".toml")
						if engine.Digest(current) != hashes[node] {
							t.Fatal("partial rollback did not preserve baseline on both peers")
						}
					}
					checkHTTP(spec.Routes[0].User.Port)
					t.Logf("Native ordinary %s: real HTTP after edit and manual restoration; preflight rejected without writes/PID change; two backups; second-peer failure restored by independent 90-second timer", edit)
				}
				return
			}
			// The executor has exited between every command; the real engine data plane persists.
			time.Sleep(2 * time.Second)
			checkHTTP(spec.Routes[0].User.Port)
			conflict := spec
			conflict.Routes = append([]engine.Route{}, spec.Routes...)
			conflict.Routes[0].User.Port = 29096
			v := require(a, "change.preflight", Change{ID: name + "_conflict", Instance: instance[a], Role: "server", ExpectedHash: hashes[a], Spec: conflict})
			var pre map[string]any
			json.Unmarshal(v.Data, &pre)
			if pre["valid"] != false {
				t.Fatal("occupied unrelated backend port accepted")
			}
			changed := spec
			changed.Routes = append([]engine.Route{}, spec.Routes...)
			changed.Routes[0].User.Port += 100
			change(name+"_timeout", changed, false)
			// Actual persistent systemd rollback timers fire without any controller/executor.
			time.Sleep(95 * time.Second)
			checkHTTP(spec.Routes[0].User.Port)
			for _, node := range nodes {
				require(node, "instance.action", map[string]any{"ID": instance[node], "Action": "stop", "ExpectedHash": hashes[node], "Confirm": true})
				require(node, "instance.action", map[string]any{"ID": instance[node], "Action": "start", "ExpectedHash": hashes[node], "Confirm": true})
			}
			checkHTTP(spec.Routes[0].User.Port)
			require(a, "logs.verbosity", map[string]any{"ID": instance[a], "Session": name + "_logging", "ExpectedHash": hashes[a], "Seconds": 60, "Level": "debug", "Confirm": true})
			// The persistent timer restores actual config/unit files with no executor.
			time.Sleep(65 * time.Second)
			require(a, "instance.action", map[string]any{"ID": instance[a], "Action": "restart", "ExpectedHash": hashes[a], "Confirm": true})
			checkHTTP(spec.Routes[0].User.Port)
			logs := require(a, "logs.read", map[string]any{"ID": instance[a], "Limit": 200, "Severity": "all"})
			var logResult struct {
				Lines []map[string]any `json:"lines"`
			}
			json.Unmarshal(logs.Data, &logResult)
			if len(logResult.Lines) == 0 || bytes.Contains(logs.Data, []byte(spec.Token)) {
				t.Fatal("actual selected-unit journal unavailable or secret leaked")
			}
			raw := run("exec", a, "cat", filepath.Join("/etc/tunnelmanager-agent/instances", instance[a]+".toml"))
			raw = append(raw, []byte("\n# manual edit\n")...)
			cmd := exec.CommandContext(ctx, "docker", "exec", "-i", a, "sh", "-c", "cat > /etc/tunnelmanager-agent/instances/"+instance[a]+".toml")
			cmd.Stdin = bytes.NewReader(raw)
			if e := cmd.Run(); e != nil {
				t.Fatal(e)
			}
			if v := call(a, "instance.action", map[string]any{"ID": instance[a], "Action": "restart", "ExpectedHash": hashes[a], "Confirm": true}); v.OK || v.Code != "manual_config_drift" {
				t.Fatal("manual config drift was not blocked")
			}
			beforeRelease := string(run("exec", a, "systemctl", "show", "tunnelmanager-instance-"+instance[a]+".service", "--property=MainPID", "--value"))
			require(a, "recovery.release", map[string]any{"ID": name + "_create", "Kind": "config", "Confirm": true})
			if beforeRelease != string(run("exec", a, "systemctl", "show", "tunnelmanager-instance-"+instance[a]+".service", "--property=MainPID", "--value")) {
				t.Fatal("recovery release restarted selected unit")
			}
			for _, node := range nodes {
				unit := "tunnelmanager-instance-" + instance[node] + ".service"
				pid := string(run("exec", node, "systemctl", "show", unit, "--property=MainPID", "--value"))
				require(node, "instance.action", map[string]any{"ID": instance[node], "Action": "revoke", "ExpectedHash": hashes[node], "Confirm": true})
				inventory := require(node, "inventory", map[string]any{"MatchKey": ""})
				var data struct {
					Instances []Discovered `json:"instances"`
				}
				json.Unmarshal(inventory.Data, &data)
				found := false
				for _, d := range data.Instances {
					if d.Unit == unit {
						found = true
						if d.Managed || d.Version != version || d.Reason != "" {
							t.Fatal("revoked service not actionable through read-only discovery")
						}
						require(node, "instance.adopt", map[string]any{"ID": d.ID, "Hash": d.Hash, "Fingerprint": d.Fingerprint, "DefinitionHash": d.DefinitionHash, "Confirm": true})
						instance[node] = d.ID
						hashes[node] = d.Hash
						break
					}
				}
				if !found {
					t.Fatal("existing native service missing from discovery")
				}
				if pid != string(run("exec", node, "systemctl", "show", unit, "--property=MainPID", "--value")) {
					t.Fatal("discovery/adoption restarted existing infrastructure")
				}
			}
			adoptedSpec := spec
			adoptedSpec.Routes = append([]engine.Route{}, spec.Routes...)
			adoptedSpec.Routes[0].User.Port += 200
			change(name+"_adopted_edit", adoptedSpec, true)
			require(a, "instance.action", map[string]any{"ID": instance[a], "Action": "remove", "ExpectedHash": hashes[a], "Confirm": true})
			t.Log("Actual engine download/checksum, two Linux systemd peers, two shared routes, HTTP data plane, unrelated port conflict, local timeout rollback, intentional stop/start and manual drift passed")
		})
	}
}
