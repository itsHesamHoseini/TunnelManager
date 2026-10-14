package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/coder/websocket"
	"github.com/itsHesamHoseini/TunnelManager/internal/protocol"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestServerPagesInBrowser(t *testing.T) {
	if os.Getenv("TUNNELMANAGER_BROWSER_TESTS") != "1" {
		t.Skip("browser opt-in")
	}
	s, srv, c := testServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	conn := fixtureNode(t, s, srv, c, ctx)
	defer conn.CloseNow()
	pub := make([]byte, 32)
	stale, _ := json.Marshal(protocol.Telemetry{At: time.Now().Add(-10 * time.Minute), OS: "Synthetic old Ubuntu sample", RAMTotal: 1024, RAMUsed: 500})
	s.DB.Exec(ctx, "INSERT INTO nodes(id,name,role,pubkey,approved,seen,telemetry)VALUES('old-fixture','Old synthetic node','iran',$1,true,now()-interval '10 minutes',$2)", pub, stale)
	s.DB.Exec(ctx, "INSERT INTO nodes(id,name,role,pubkey,approved)VALUES('pending-fixture','Pending synthetic node','foreign',$1,false)", pub)
	cmd := exec.Command("node", "web/tests/servers.mjs")
	cmd.Dir = filepath.Join("..", "..")
	cmd.Env = append(os.Environ(), "TUNNELMANAGER_TEST_URL="+srv.URL)
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("server browser failed: %v\n%s", e, out)
	}
}
func fixtureNode(t *testing.T, s *Server, srv *httptest.Server, c *http.Client, ctx context.Context) *websocket.Conn {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	s.DB.Exec(ctx, "INSERT INTO nodes(id,name,role,pubkey,approved)VALUES('live-fixture','Live synthetic node','foreign',$1,true)", pub)
	conn, _, e := websocket.Dial(ctx, "wss"+srv.URL[5:]+"/api/agent", &websocket.DialOptions{HTTPClient: c})
	if e != nil {
		t.Fatal(e)
	}
	_, b, e := conn.Read(ctx)
	if e != nil {
		t.Fatal(e)
	}
	var h protocol.Hello
	json.Unmarshal(b, &h)
	msg := "live-fixture\n" + h.Nonce + "\n" + h.Expires.UTC().Format(time.RFC3339Nano)
	b, _ = json.Marshal(protocol.Authentication{NodeID: "live-fixture", Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(msg)))})
	conn.Write(ctx, websocket.MessageText, b)
	value := 17.5
	rate := 4096.0
	d := protocol.Telemetry{At: time.Now(), OS: "Synthetic Ubuntu sample", CPU: &value, RAMTotal: 1073741824, RAMUsed: 268435456, DiskTotal: 10737418240, DiskFree: 5368709120, Processes: []protocol.Process{{PID: 42, Name: "backhaul-fixture", RAM: 8388608, Engine: true}}, Listeners: []protocol.Listener{{Address: "192.0.2.20:443", Protocol: "tcp", Process: "backhaul-fixture", PID: 42}, {Address: "192.0.2.20:5300", Protocol: "udp", Process: "fixture-other", PID: 50}}, SocketStates: map[string]int{"ESTAB": 4, "LISTEN": 2}, Services: []protocol.Service{{Name: "backhaul-fixture.service", Active: "active", Enabled: "enabled"}}}
	d.Networks = []protocol.Network{{Name: "eth0", Primary: true, RX: 10000, TX: 20000, RXRate: &rate, TXRate: &rate}}
	older, _ := json.Marshal(d)
	s.DB.Exec(ctx, "INSERT INTO measurements(node_id,at,data)VALUES('live-fixture',now()-interval '30 seconds',$1)", older)
	b, _ = json.Marshal(protocol.Frame{Type: "telemetry", Version: 1, Data: &d})
	conn.Write(ctx, websocket.MessageText, b)
	if _, _, e = conn.Read(ctx); e != nil {
		t.Fatal(e)
	}
	return conn
}
