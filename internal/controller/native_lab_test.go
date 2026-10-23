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
	"github.com/itsHesamHoseini/TunnelManager/internal/engine"
	"github.com/itsHesamHoseini/TunnelManager/internal/nodeops"
	"github.com/itsHesamHoseini/TunnelManager/internal/secure"
	"math/big"
	"net"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestNativeControllerBrowserWorkflow(t *testing.T) {
	if os.Getenv("CI") != "true" || os.Getenv("TUNNELMANAGER_NATIVE_LAB") != "1" {
		t.Skip("isolated CI only")
	}
	s, _, _ := testServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 23*time.Minute)
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
		run("exec", node, "systemd-run", "--unit=lab-backend-alt", "python3", "-m", "http.server", "29097", "--bind", "127.0.0.1", "--directory", "/lab/public")
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
		for _, engine := range []string{"backhaul"} {
			version := "0.7.2"
			body, _ := json.Marshal(map[string]string{"Engine": engine, "Version": version})
			id, e := s.newJob(ctx, "install_"+node+"_"+engine, "node", node, "Install", JobPayload{Node: node, Kind: "engine.install", Payload: body})
			if e != nil {
				t.Fatal(e)
			}
			wait(id)
		}
	}
	certificatePayload, _ := json.Marshal(CertificateRequest{Name: "Synthetic transport TLS", Domain: "transport.example.com", Method: "self-signed", Days: 2})
	certificateJob, e := s.newJob(ctx, "native_certificate_issue", "certificate", "native_tls", "Synthetic TLS", JobPayload{Kind: "issue", Certificate: "native_tls", Payload: certificatePayload})
	if e != nil {
		t.Fatal(e)
	}
	wait(certificateJob)
	deployPayload, _ := json.Marshal([]CertificateDeployment{{Node: ids[0], TrustOnly: false}, {Node: ids[1], TrustOnly: true}})
	deployJob, e := s.newJob(ctx, "native_certificate_deploy", "certificate", "native_tls", "Deploy synthetic TLS", JobPayload{Kind: "deploy", Certificate: "native_tls", ExpectedRevision: 1, Payload: deployPayload})
	if e != nil {
		t.Fatal(e)
	}
	wait(deployJob)
	fixture := map[string]any{"url": srv.URL, "recovery": codes[0], "listener": ids[0], "dialer": ids[1], "listener_ip": ips[0], "dialer_ip": ips[1]}
	fixture["certificate"] = "native_tls"
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
	batchRevisions := map[string]int64{}
	for _, name := range []string{"Synthetic native backhaul tcp", "Synthetic native backhaul wss"} {
		var id string
		var rev int64
		if s.DB.QueryRow(ctx, "SELECT id,revision FROM tunnels WHERE name=$1", name).Scan(&id, &rev) != nil {
			t.Fatal("batch tunnel missing")
		}
		batchRevisions[id] = rev
	}
	status, batch := request(t, client, srv.URL+"/api/tunnel-actions", "POST", map[string]any{"RequestKey": "native_batch_restart", "Action": "restart", "Revisions": batchRevisions, "Confirm": true})
	if status != 200 {
		t.Fatal("native batch rejected")
	}
	batchID, _ := batch["operation_id"].(string)
	wait(batchID)
	var executed int
	s.DB.QueryRow(ctx, "SELECT count(*) FROM commands WHERE operation_id=$1 AND kind='instance.action' AND state='completed'", batchID).Scan(&executed)
	if executed != 4 {
		t.Fatal("batch did not execute exactly once on four selected instances")
	}
	applyPlan := func(body map[string]any) string {
		t.Helper()
		status, reply := request(t, client, srv.URL+"/api/tunnel-plans", "POST", body)
		if status != 200 {
			t.Fatalf("native plan rejected: %v", reply["message"])
		}
		operation, _ := reply["operation_id"].(string)
		for _, transition := range []struct{ phase, action string }{{"ready", "apply"}, {"awaiting_confirmation", "confirm"}} {
			ready := false
			for attempt := 0; attempt < 100; attempt++ {
				var phase, code string
				s.DB.QueryRow(ctx, "SELECT phase,error FROM operations WHERE id=$1", operation).Scan(&phase, &code)
				if phase == transition.phase {
					ready = true
					break
				}
				if phase == "failed" || phase == "needs_review" {
					t.Fatal("native plan: " + code)
				}
				time.Sleep(time.Second)
			}
			if !ready {
				t.Fatal("native plan phase timeout: " + transition.phase)
			}
			status, _ = request(t, client, srv.URL+"/api/operations/"+operation+"/transition", "POST", map[string]any{"Action": transition.action, "Confirm": true})
			if status != 200 {
				t.Fatal("native transition rejected")
			}
		}
		wait(operation)
		target, _ := reply["tunnel_id"].(string)
		return target
	}
	var originalID string
	s.DB.QueryRow(ctx, "SELECT id FROM tunnels WHERE name='Synthetic native backhaul tcp'").Scan(&originalID)
	original, rev, _, e := s.readTunnel(ctx, originalID)
	if e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"tcp", "tls"} {
		status, body := request(t, client, srv.URL+"/api/tunnels/"+originalID+"/entry-check", "POST", map[string]any{"RequestKey": "native_entry_" + kind, "ExpectedRevision": rev, "Mapping": original.Spec.Routes[0].ID, "Kind": kind})
		if status != 200 {
			t.Fatal("native entry check rejected")
		}
		id := body["operation_id"].(string)
		wait(id)
		var result []byte
		s.DB.QueryRow(ctx, "SELECT result FROM operations WHERE id=$1", id).Scan(&result)
		var observed map[string]any
		json.Unmarshal(result, &observed)
		expected := "passed"
		if kind == "tls" {
			expected = "failed"
		} // Actual backend is HTTP, not TLS.
		if observed["entry_check"] != true || observed["status"] != expected || observed["source"] != original.Spec.Dialer || observed["target"] != net.JoinHostPort(original.Spec.TransportRemote.Host, strconv.Itoa(original.Spec.Routes[0].User.Port)) {
			t.Fatal("native entry check did not retain actual scope/result")
		}
	}
	t.Log("Actual user entry TCP passed from destination peer; strict TLS to the HTTP backend failed as expected. Neither result asserts VLESS health.")
	for _, version := range []int64{1, 2} {
		applyPlan(map[string]any{"RequestKey": fmt.Sprintf("native_version_%d", version), "Tunnel": originalID, "Name": "Synthetic native backhaul tcp", "Spec": original.Spec, "ExpectedRevision": rev, "RevertRevision": version})
		_, rev, _, _ = s.readTunnel(ctx, originalID)
	}
	clone := original.Spec
	clone.Token = ""
	clone.Routes = append([]engine.Route{}, clone.Routes...)
	for i := range clone.Routes {
		clone.Routes[i].User.Port += 200
	}
	clone.TransportBind.Port = 28200
	clone.TransportRemote.Port = 28200
	probe := *clone.Application
	probe.Endpoint.Port = clone.Routes[0].User.Port
	clone.Application = &probe
	cloneID := applyPlan(map[string]any{"RequestKey": "native_clone", "Name": "Synthetic cloned route", "Spec": clone})
	cloned, cloneRevision, _, e := s.readTunnel(ctx, cloneID)
	if e != nil || cloned.Spec.Token == original.Spec.Token {
		t.Fatal("clone reused private authentication")
	}
	for _, action := range []string{"disable", "start", "remove"} {
		status, result := request(t, client, srv.URL+"/api/tunnels/"+cloneID+"/actions", "POST", map[string]any{"RequestKey": "native_clone_" + action, "Action": action, "ExpectedRevision": cloneRevision, "Confirm": true})
		if status != 200 {
			t.Fatal("native clone action rejected: " + action)
		}
		job, _ := result["operation_id"].(string)
		wait(job)
	}
	if _, _, _, e = s.readTunnel(ctx, cloneID); e == nil {
		t.Fatal("removed clone retained as managed")
	}
	t.Log("Real API clone generated independent identities; native version restoration, batch exactly-once actions, disable/start and owned removal passed")
	// A real pre-existing service with no peer can be managed after an explicit
	// metadata-only adoption. It is not silently rewritten as a panel-created unit.
	orphan := original.Spec
	orphan.Transport = "tcp"
	orphan.TransportRemote = engine.Endpoint{Host: "127.0.0.1", Port: 65534}
	orphan.Routes = append([]engine.Route{}, orphan.Routes...)
	orphan.Routes[0].ID = "unmatched"
	orphan.Token = "synthetic-unmatched-fixture"
	orphan.PeerOptions = nil
	orphanRaw, e := engine.Render(orphan, "client")
	if e != nil {
		t.Fatal(e)
	}
	writeFixture := func(path, data string) {
		cmd := exec.CommandContext(ctx, "docker", "exec", "-i", nodes[1], "sh", "-c", "umask 077; cat > "+path)
		cmd.Stdin = strings.NewReader(data)
		if out, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("native fixture file: %v %s", e, out)
		}
	}
	writeFixture("/etc/tunnelmanager-lab-orphan.toml", orphanRaw)
	writeFixture("/etc/systemd/system/synthetic-orphan.service", "[Unit]\nDescription=Synthetic unpaired existing engine\n[Service]\nExecStart=/opt/tunnelmanager/engines/backhaul/0.7.2/backhaul -c /etc/tunnelmanager-lab-orphan.toml\nRestart=no\n")
	run("exec", nodes[1], "systemctl", "daemon-reload")
	run("exec", nodes[1], "systemctl", "start", "synthetic-orphan")
	beforeOrphan := string(run("exec", nodes[1], "systemctl", "show", "synthetic-orphan", "--property=MainPID", "--value"))
	nodeAction := func(key, kind string, payload any) string {
		status, result := request(t, client, srv.URL+"/api/nodes/"+ids[1]+"/actions", "POST", map[string]any{"request_key": key, "kind": kind, "payload": payload, "confirm": true})
		if status != 200 {
			t.Fatalf("native node action rejected: %s", kind)
		}
		id, _ := result["operation_id"].(string)
		return id
	}
	wait(nodeAction("native_orphan_discover", "inventory", map[string]any{}))
	var inventoryRaw []byte
	s.DB.QueryRow(ctx, "SELECT inventory FROM nodes WHERE id=$1", ids[1]).Scan(&inventoryRaw)
	var discovered struct {
		Instances []nodeops.Discovered `json:"instances"`
	}
	json.Unmarshal(inventoryRaw, &discovered)
	var found *nodeops.Discovered
	for i := range discovered.Instances {
		if discovered.Instances[i].Unit == "synthetic-orphan.service" {
			found = &discovered.Instances[i]
			break
		}
	}
	if found == nil || found.Managed {
		t.Fatal("unpaired existing service missing")
	}
	wait(nodeAction("native_orphan_adopt", "instance.adopt", map[string]any{"ID": found.ID, "Name": "Synthetic orphan service"}))
	if beforeOrphan != string(run("exec", nodes[1], "systemctl", "show", "synthetic-orphan", "--property=MainPID", "--value")) {
		t.Fatal("adoption restarted unpaired service")
	}
	for _, action := range []string{"stop", "start"} {
		wait(nodeAction("native_orphan_"+action, "instance.action", map[string]any{"ID": found.ID, "Action": action, "ExpectedHash": found.Hash, "Confirm": true}))
	}
	protectedRemove := nodeAction("native_orphan_remove_guard", "instance.action", map[string]any{"ID": found.ID, "Action": "remove", "ExpectedHash": found.Hash, "Confirm": true})
	for attempt := 0; attempt < 30; attempt++ {
		var phase, code string
		s.DB.QueryRow(ctx, "SELECT phase,error FROM operations WHERE id=$1", protectedRemove).Scan(&phase, &code)
		if phase == "failed" {
			if code != "adopted_instance_preserved_stop_or_revoke_instead" {
				t.Fatal("wrong original-unit protection result")
			}
			break
		}
		if phase == "succeeded" || attempt == 29 {
			t.Fatal("foreign unit removal not protected")
		}
		time.Sleep(time.Second)
	}
	t.Log("Real unpaired foreign service: signed discovery, explicit named adoption without PID changes, actual stop/start and original-unit removal protection passed")
	shared := original.Spec
	shared.Transport = "tcp"
	shared.Token = "synthetic-native-shared-auth"
	shared.PeerOptions = nil
	shared.TransportBind.Port = 28300
	shared.TransportRemote.Port = 28300
	shared.Application = nil
	shared.Routes = []engine.Route{{ID: "shared_one", Name: "Shared first", User: engine.Endpoint{Host: "0.0.0.0", Port: 24843}, Backend: engine.Endpoint{Host: "127.0.0.1", Port: 29096}, Protocol: "tcp"}, {ID: "shared_two", Name: "Shared second", User: engine.Endpoint{Host: "0.0.0.0", Port: 24844}, Backend: engine.Endpoint{Host: "127.0.0.1", Port: 29096}, Protocol: "tcp"}}
	writeAt := func(node, path, data string) {
		cmd := exec.CommandContext(ctx, "docker", "exec", "-i", node, "sh", "-c", "umask 077; cat > "+path)
		cmd.Stdin = strings.NewReader(data)
		if e := cmd.Run(); e != nil {
			t.Fatal("shared fixture write failed")
		}
	}
	for index, unit := range []string{"synthetic-shared-server", "synthetic-shared-first", "synthetic-shared-second"} {
		spec := shared
		role := "server"
		node := nodes[0]
		if index > 0 {
			role = "client"
			node = nodes[1]
			spec.Routes = shared.Routes[index-1 : index]
			spec.PeerOptions = map[string]map[string]any{"client": {"retry_interval": float64(index + 1)}}
		}
		raw, e := engine.Render(spec, role)
		if e != nil {
			t.Fatal(e)
		}
		path := "/etc/" + unit + ".toml"
		writeAt(node, path, raw)
		writeAt(node, "/etc/systemd/system/"+unit+".service", "[Unit]\nDescription=Synthetic existing shared instance\n[Service]\nExecStart=/opt/tunnelmanager/engines/backhaul/0.7.2/backhaul -c "+path+"\nRestart=no\n")
		run("exec", node, "systemctl", "daemon-reload")
		run("exec", node, "systemctl", "start", unit)
	}
	for index, node := range ids {
		status, result := request(t, client, srv.URL+"/api/nodes/"+node+"/actions", "POST", map[string]any{"request_key": fmt.Sprintf("native_shared_discover_%d", index), "kind": "inventory", "payload": map[string]any{}})
		if status != 200 {
			t.Fatal("shared discovery rejected")
		}
		op, _ := result["operation_id"].(string)
		wait(op)
	}
	sharedIDs := []string{}
	adoptedVersions := map[string]int64{}
	for _, entry := range []struct{ unit, name string }{{"synthetic-shared-first.service", "Synthetic shared first"}, {"synthetic-shared-second.service", "Synthetic shared second"}} {
		var inventory []byte
		s.DB.QueryRow(ctx, "SELECT inventory FROM nodes WHERE id=$1", ids[1]).Scan(&inventory)
		var data struct {
			Instances []nodeops.Discovered `json:"instances"`
		}
		json.Unmarshal(inventory, &data)
		instance := ""
		for _, v := range data.Instances {
			if v.Unit == entry.unit {
				instance = v.ID
			}
		}
		if instance == "" {
			t.Fatal("second native client missing")
		}
		var serverInventory []byte
		s.DB.QueryRow(ctx, "SELECT inventory FROM nodes WHERE id=$1", ids[0]).Scan(&serverInventory)
		json.Unmarshal(serverInventory, &data)
		serverInstance := ""
		for _, v := range data.Instances {
			if v.Unit == "synthetic-shared-server.service" {
				serverInstance = v.ID
			}
		}
		status, result := request(t, client, srv.URL+"/api/tunnel-imports", "POST", map[string]any{"Name": entry.name, "Listener": ids[0], "Dialer": ids[1], "ServerInstance": serverInstance, "ClientInstance": instance})
		if status != 200 {
			t.Fatal("shared manual import rejected")
		}
		id, _ := result["tunnel_id"].(string)
		_, revision, _, _ := s.readTunnel(ctx, id)
		// The read-only preview and metadata adoption must retain both actual
		// configurations and process identities, including the shared listener.
		protected := func() string {
			return string(run("exec", nodes[0], "systemctl", "show", "synthetic-shared-server", "-p", "MainPID")) + string(run("exec", nodes[1], "systemctl", "show", entry.unit, "-p", "MainPID")) + string(run("exec", nodes[0], "sha256sum", "/etc/synthetic-shared-server.toml")) + string(run("exec", nodes[1], "sha256sum", "/etc/"+strings.TrimSuffix(entry.unit, ".service")+".toml"))
		}
		before := protected()
		status, result = request(t, client, srv.URL+"/api/tunnels/"+id+"/adoption-preview", "POST", map[string]any{"RequestKey": "native_preview_" + instance, "ExpectedRevision": revision})
		if status != 200 {
			t.Fatal("shared adoption preview rejected")
		}
		preview, _ := result["operation_id"].(string)
		wait(preview)
		var previewMutations int
		s.DB.QueryRow(ctx, "SELECT count(*) FROM commands WHERE operation_id=$1 AND kind<>'inventory'", preview).Scan(&previewMutations)
		if previewMutations != 0 || protected() != before {
			t.Fatal("adoption preview changed real infrastructure")
		}
		status, result = request(t, client, srv.URL+"/api/tunnels/"+id+"/adopt", "POST", map[string]any{"RequestKey": "native_adopt_" + instance, "ExpectedRevision": revision, "Confirm": true, "Preview": preview})
		if status != 200 {
			t.Fatal("shared adoption rejected")
		}
		op, _ := result["operation_id"].(string)
		wait(op)
		if protected() != before {
			t.Fatal("adoption changed configuration or process identity")
		}
		_, adoptedVersions[id], _, e = s.readTunnel(ctx, id)
		if e != nil {
			t.Fatal(e)
		}
		var savedVersion bool
		s.DB.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM tunnel_versions WHERE tunnel_id=$1 AND revision=$2)", id, adoptedVersions[id]).Scan(&savedVersion)
		if !savedVersion {
			t.Fatal("exact adopted baseline was not saved")
		}
		sharedIDs = append(sharedIDs, id)
	}
	for index, id := range sharedIDs {
		record, revision, _, e := s.readTunnel(ctx, id)
		if e != nil {
			t.Fatal(e)
		}
		record.Spec.Routes[index].User.Port = 24845 + index
		record.Spec.Application = &engine.Probe{Kind: "http", Endpoint: engine.Endpoint{Host: ips[0], Port: 24845 + index}, Path: "/probe", Expected: "synthetic-native-response"}
		applyPlan(map[string]any{"RequestKey": fmt.Sprintf("native_shared_edit_%d", index), "Tunnel": id, "Name": []string{"Synthetic shared first", "Synthetic shared second"}[index], "Spec": record.Spec, "ExpectedRevision": revision})
		for _, unit := range []string{"synthetic-shared-server", "synthetic-shared-first", "synthetic-shared-second"} {
			container := nodes[1]
			if unit == "synthetic-shared-server" {
				container = nodes[0]
			}
			run("exec", container, "systemctl", "is-active", unit)
		}
	}
	for _, port := range []string{"24845", "24846"} {
		run("exec", nodes[1], "python3", "-c", "import urllib.request; assert b'synthetic-native-response' in urllib.request.urlopen('http://"+ips[0]+":"+port+"/probe',timeout=5).read()")
	}
	t.Log("Real shared listener and two independent clients on the same node imported/adopted; both route edits preserved the other route, scoped options and per-instance revision hashes")
	first, revision, _, e := s.readTunnel(ctx, sharedIDs[0])
	if e != nil {
		t.Fatal(e)
	}
	applyPlan(map[string]any{"RequestKey": "native_restore_adopted_baseline", "Tunnel": sharedIDs[0], "Name": "Synthetic shared first", "Spec": first.Spec, "ExpectedRevision": revision, "RevertRevision": adoptedVersions[sharedIDs[0]]})
	for _, port := range []string{"24843", "24844"} {
		run("exec", nodes[1], "python3", "-c", "import urllib.request; assert b'synthetic-native-response' in urllib.request.urlopen('http://"+ips[0]+":"+port+"/probe',timeout=5).read()")
	}
	t.Log("Native discovery -> read-only preview -> explicit adoption -> shared edit -> adopted baseline restore: unchanged preview/adoption PIDs/configs and real HTTP on both restored entries")
	status, _ = request(t, client, srv.URL+"/api/certificates/native_tls/policy", "PUT", map[string]any{"expected_policy_revision": 0, "auto_deploy": true, "confirm": true})
	if status != 200 {
		t.Fatal("explicit automatic deployment policy was not saved")
	}
	// Renew and deploy a new identity to every real TLS consumer. A stopped
	// consumer must remain stopped throughout coordinated certificate rotation.
	var tlsTunnel string
	s.DB.QueryRow(ctx, "SELECT id FROM tunnels WHERE name='Synthetic native backhaul wss'").Scan(&tlsTunnel)
	tlsRecord, _, _, e := s.readTunnel(ctx, tlsTunnel)
	if e != nil {
		t.Fatal(e)
	}
	tlsInstance := tlsRecord.Instances[ids[0]]
	tlsUserPorts := []string{}
	for _, route := range tlsRecord.Spec.Routes {
		tlsUserPorts = append(tlsUserPorts, strconv.Itoa(route.User.Port))
	}
	intent := func(action, suffix string) {
		payload, _ := json.Marshal(map[string]any{"ID": tlsInstance, "Action": action, "ExpectedHash": tlsRecord.Hashes[ids[0]], "Confirm": true})
		job, err := s.newJob(ctx, "native_tls_"+suffix, "node", ids[0], "TLS consumer "+action, JobPayload{Node: ids[0], Kind: "instance.action", Payload: payload})
		if err != nil {
			t.Fatal(err)
		}
		wait(job)
	}
	intent("stop", "stop_for_renewal")
	certificatePayload, _ = json.Marshal(CertificateRequest{Name: "Synthetic transport TLS", Domain: "transport.example.com", Method: "self-signed", Days: 3, AutoDeploy: true})
	renewJob, e := s.newJob(ctx, "native_certificate_renew", "certificate", "native_tls", "Renew synthetic TLS", JobPayload{Kind: "issue", Certificate: "native_tls", ExpectedRevision: 1, Payload: certificatePayload})
	if e != nil {
		t.Fatal(e)
	}
	wait(renewJob)
	var rotation string
	for attempt := 0; attempt < 10; attempt++ {
		s.DB.QueryRow(ctx, "SELECT id FROM operations WHERE target='native_tls' AND kind='certificate' AND id<>$1 AND created>(SELECT created FROM operations WHERE id=$1) ORDER BY created DESC LIMIT 1", renewJob).Scan(&rotation)
		if rotation != "" {
			break
		}
		time.Sleep(time.Second)
	}
	if rotation == "" {
		t.Fatal("automatic linked certificate deployment missing")
	}
	wait(rotation)
	active, _ := exec.CommandContext(ctx, "docker", "exec", nodes[0], "systemctl", "is-active", "tunnelmanager-instance-"+tlsInstance+".service").Output()
	if strings.TrimSpace(string(active)) != "inactive" {
		t.Fatal("certificate rotation overrode intentional stop")
	}
	run("exec", nodes[1], "sh", "-c", "test ! -e /etc/tunnelmanager-agent/certificates/native_tls/key.pem")
	intent("start", "start_after_renewal")
	for _, p := range tlsUserPorts {
		run("exec", nodes[1], "python3", "-c", "import urllib.request; assert b'synthetic-native-response' in urllib.request.urlopen('http://"+ips[0]+":"+p+"/probe',timeout=5).read()")
	}
	t.Log("Real self-signed TLS/WSS issuance, deployment, linked renewal and automatic coordinated rotation passed; stopped consumer and client private-key isolation preserved")
	// Activate a different listener identity without client trust in this disposable
	// lab, then stop its agent. The native systemd timer must restore real traffic.
	priorCert, _, e := s.readCertificate(ctx, "native_tls")
	if e != nil {
		t.Fatal(e)
	}
	candidate := priorCert
	if e = makeSelfSigned(&candidate); e != nil {
		t.Fatal(e)
	}
	var previousHash string
	s.DB.QueryRow(ctx, "SELECT hash FROM certificate_links WHERE certificate_id='native_tls' AND node_id=$1 LIMIT 1", ids[0]).Scan(&previousHash)
	consumerRows, e := s.DB.Query(ctx, "SELECT instance_id FROM certificate_links WHERE certificate_id='native_tls' AND node_id=$1 AND instance_id<>''", ids[0])
	if e != nil {
		t.Fatal(e)
	}
	consumers := []string{}
	for consumerRows.Next() {
		var id string
		consumerRows.Scan(&id)
		consumers = append(consumers, id)
	}
	consumerRows.Close()
	certificateStep := func(stage string, p nodeops.Certificate) {
		p.ID = "native_tls"
		p.RequestID = "native_local_cert_rollback"
		p.Stage = stage
		p.Confirm = true
		raw, _ := json.Marshal(p)
		job, e := s.newJob(ctx, "native_cert_timeout_"+stage, "node", ids[0], "Native timed certificate "+stage, JobPayload{Node: ids[0], Kind: "certificate.deploy", Payload: raw})
		if e != nil {
			t.Fatal(e)
		}
		wait(job)
	}
	certificateStep("prepare", nodeops.Certificate{Domain: candidate.Domain, Cert: candidate.Cert, Key: candidate.Key, ExpectedHash: previousHash, Instances: consumers})
	certificateStep("activate", nodeops.Certificate{Deadline: time.Now().Add(30 * time.Second)})
	run("exec", nodes[0], "systemctl", "stop", "tunnelmanager-agent")
	time.Sleep(35 * time.Second)
	for _, p := range tlsUserPorts {
		run("exec", nodes[1], "python3", "-c", "import urllib.request; assert b'synthetic-native-response' in urllib.request.urlopen('http://"+ips[0]+":"+p+"/probe',timeout=5).read()")
	}
	run("exec", nodes[0], "systemctl", "start", "tunnelmanager-agent")
	for attempt := 0; attempt < 90 && !s.isConnected(ids[0]); attempt++ {
		time.Sleep(time.Second)
	}
	if !s.isConnected(ids[0]) {
		t.Fatal("agent did not reconnect after native certificate timeout")
	}
	t.Log("Actual listener certificate mutation reverted through an independent systemd timer with its agent stopped; real TLS/WSS HTTP paths recovered")
	// A real per-service RAM policy continues while the control route is blackholed.
	var tunnelID string
	if s.DB.QueryRow(ctx, "SELECT id FROM tunnels WHERE name='Synthetic native backhaul tcp'").Scan(&tunnelID) != nil {
		t.Fatal("native Backhaul tunnel missing")
	}
	record, _, _, e := s.readTunnel(ctx, tunnelID)
	if e != nil {
		t.Fatal(e)
	}
	instance := record.Instances[ids[0]]
	unit := "tunnelmanager-instance-" + instance + ".service"
	before := strings.TrimSpace(string(run("exec", nodes[0], "systemctl", "show", unit, "--property=MainPID", "--value")))
	backendBefore := strings.TrimSpace(string(run("exec", nodes[0], "systemctl", "show", "lab-backend.service", "--property=MainPID", "--value")))
	policyPayload, _ := json.Marshal(nodeops.RecoveryPolicy{ID: instance, Enabled: true, RAM: 1, SustainedSeconds: 60, CooldownSeconds: 120, DailyLimit: 1})
	policyJob, e := s.newJob(ctx, "native_recovery_policy", "node", ids[0], "Native recovery policy", JobPayload{Node: ids[0], Kind: "recovery.policy", Payload: policyPayload})
	if e != nil {
		t.Fatal(e)
	}
	wait(policyJob)
	hostFields := strings.Fields(string(run("exec", nodes[0], "getent", "hosts", "controller.example.com")))
	if len(hostFields) == 0 || net.ParseIP(hostFields[0]) == nil {
		t.Fatal("lab controller route missing")
	}
	hostRoute := hostFields[0] + "/32"
	run("exec", nodes[0], "ip", "route", "add", "blackhole", hostRoute)
	policyPath := "/var/lib/tunnelmanager-agent/recovery/" + instance + ".json"
	restarted := false
	for attempt := 0; attempt < 26; attempt++ {
		var policy nodeops.RecoveryPolicy
		if json.Unmarshal(run("exec", nodes[0], "cat", policyPath), &policy) == nil && policy.Count == 1 {
			restarted = true
			break
		}
		time.Sleep(5 * time.Second)
	}
	run("exec", nodes[0], "ip", "route", "del", "blackhole", hostRoute)
	if !restarted {
		t.Fatal("sustained RAM policy did not recover service during controller disconnection")
	}
	after := strings.TrimSpace(string(run("exec", nodes[0], "systemctl", "show", unit, "--property=MainPID", "--value")))
	if before == after || after == "0" {
		t.Fatal("selected service was not restarted")
	}
	backendAfter := strings.TrimSpace(string(run("exec", nodes[0], "systemctl", "show", "lab-backend.service", "--property=MainPID", "--value")))
	if backendBefore != backendAfter {
		t.Fatal("unrelated service restarted")
	}
	for attempt := 0; attempt < 90 && !s.isConnected(ids[0]); attempt++ {
		time.Sleep(time.Second)
	}
	if !s.isConnected(ids[0]) {
		t.Fatal("agent did not securely reconnect")
	}
	for _, action := range []string{"stop", "start"} {
		payload, _ := json.Marshal(map[string]any{"ID": instance, "Action": action, "ExpectedHash": record.Hashes[ids[0]], "Confirm": true})
		job, e := s.newJob(ctx, "native_intent_"+action, "node", ids[0], "Intentional "+action, JobPayload{Node: ids[0], Kind: "instance.action", Payload: payload})
		if e != nil {
			t.Fatal(e)
		}
		wait(job)
		if action == "stop" {
			time.Sleep(65 * time.Second)
			active, _ := exec.CommandContext(ctx, "docker", "exec", nodes[0], "systemctl", "is-active", unit).Output()
			if strings.TrimSpace(string(active)) != "inactive" {
				t.Fatal("automatic recovery overrode an intentional stop")
			}
		}
	}
	t.Log("Actual native RAM samples triggered only the selected unit after sustained duration during a controller-route outage; another service PID and an intentional stop were preserved")
	// Stop both control agents after confirmation. Actual HTTP data plane persists.
	for _, node := range nodes {
		run("exec", node, "systemctl", "stop", "tunnelmanager-agent")
	}
	run("exec", nodes[1], "python3", "-c", "import urllib.request; assert b'synthetic-native-response' in urllib.request.urlopen('http://"+ips[0]+":24543/probe',timeout=5).read()")
	t.Log("Real controller/PostgreSQL/browser -> signed outbound TLS agents -> two Linux systemd peers and Backhaul TCP/WSS passed; data plane works with both agents stopped")
}
