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
		case "backend":
			http.ListenAndServe("0.0.0.0:29096", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "lab-response") }))
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
func TestNativeBothEngines(t *testing.T) {
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
	for index, name := range []string{"backhaul", "rathole"} {
		t.Run(name, func(t *testing.T) {
			version := map[string]string{"backhaul": "0.7.2", "rathole": "0.5.0"}[name]
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
			t.Log("Actual engine download/checksum, two Linux systemd peers, two shared routes, HTTP data plane, unrelated port conflict, local timeout rollback, intentional stop/start and manual drift passed")
		})
	}
}
