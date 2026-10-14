package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/coder/websocket"
	"github.com/itsHesamHoseini/TunnelManager/internal/protocol"
	"testing"
	"time"
)

func TestSignedChannelRejectsPendingAndAcceptsApproved(t *testing.T) {
	s, srv, c := testServer(t)
	token, _ := s.CreateEnrollment(context.Background(), "Synthetic node", "foreign", false)
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	status, b := request(t, c, srv.URL+"/api/enroll", "POST", map[string]string{"token": token, "public_key": base64.RawURLEncoding.EncodeToString(pub)})
	if status != 200 {
		t.Fatal(status)
	}
	id := b["node_id"].(string)
	var previousProof []byte
	connect := func() (*websocket.Conn, context.Context, context.CancelFunc) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		conn, _, e := websocket.Dial(ctx, "wss"+srv.URL[5:]+"/api/agent", &websocket.DialOptions{HTTPClient: c})
		if e != nil {
			t.Fatal(e)
		}
		_, b, e := conn.Read(ctx)
		if e != nil {
			t.Fatal(e)
		}
		var hello protocol.Hello
		json.Unmarshal(b, &hello)
		msg := id + "\n" + hello.Nonce + "\n" + hello.Expires.UTC().Format(time.RFC3339Nano)
		b, _ = json.Marshal(protocol.Authentication{NodeID: id, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(msg)))})
		previousProof = append([]byte(nil), b...)
		if e = conn.Write(ctx, websocket.MessageText, b); e != nil {
			t.Fatal(e)
		}
		return conn, ctx, cancel
	}
	conn, ctx, cancel := connect()
	if _, _, e := conn.Read(ctx); e == nil {
		t.Fatal("pending node accepted")
	}
	conn.CloseNow()
	cancel()
	s.DB.Exec(context.Background(), "UPDATE nodes SET approved=true WHERE id=$1", id)
	// The old valid proof is bound to the previous connection's nonce.
	replayCtx, replayCancel := context.WithTimeout(context.Background(), 5*time.Second)
	replay, _, err := websocket.Dial(replayCtx, "wss"+srv.URL[5:]+"/api/agent", &websocket.DialOptions{HTTPClient: c})
	if err != nil {
		t.Fatal(err)
	}
	replay.Read(replayCtx)
	replay.Write(replayCtx, websocket.MessageText, previousProof)
	if _, _, e := replay.Read(replayCtx); e == nil {
		t.Fatal("old identity proof replay accepted")
	}
	replay.CloseNow()
	replayCancel()
	conn, ctx, cancel = connect()
	defer cancel()
	defer conn.CloseNow()
	frame := protocol.Frame{Type: "telemetry", Version: 1, Data: &protocol.Telemetry{At: time.Now(), Scope: "synthetic test only"}}
	data, _ := json.Marshal(frame)
	if e := conn.Write(ctx, websocket.MessageText, data); e != nil {
		t.Fatal(e)
	}
	_, ack, e := conn.Read(ctx)
	if e != nil {
		t.Fatal("approved node failed", e)
	}
	if string(ack) != "{\"type\":\"accepted\"}" {
		t.Fatal("missing ACK")
	}
	var samples int
	s.DB.QueryRow(context.Background(), "SELECT count(*) FROM measurements WHERE node_id=$1", id).Scan(&samples)
	if samples != 1 {
		t.Fatal("not persisted")
	}
	duplicate, duplicateCtx, duplicateCancel := connect()
	if _, _, e := duplicate.Read(duplicateCtx); e == nil {
		t.Fatal("duplicate identity connection accepted")
	}
	duplicate.CloseNow()
	duplicateCancel()
	data, _ = json.Marshal(map[string]any{"type": "shell", "command": "synthetic forbidden action"})
	conn.Write(ctx, websocket.MessageText, data)
	if _, _, e = conn.Read(ctx); e == nil {
		t.Fatal("arbitrary action accepted")
	}
}
