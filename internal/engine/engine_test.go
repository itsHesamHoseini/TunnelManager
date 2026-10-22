package engine

import (
	"strings"
	"testing"
)

func fixture(name string) Spec {
	return Spec{Engine: name, Version: "0.7.2", Transport: "tcp", Listener: "listener", Dialer: "dialer", TransportBind: Endpoint{"0.0.0.0", 28100}, TransportRemote: Endpoint{"listener.example.com", 28100}, Token: "synthetic-token-not-a-credential", Routes: []Route{{ID: "one", Name: "First", User: Endpoint{"0.0.0.0", 24443}, Backend: Endpoint{"127.0.0.1", 2096}, Protocol: "tcp"}}}
}
func TestRedactUnsupportedNestedArrayTables(t *testing.T) {
	raw := "[client]\nremote_addr='example.com:28100'\ntoken='synthetic-top-level-secret'\n[[client.extensions]]\nname='kept-evidence'\npassword='synthetic-nested-password'\nitems=[{api_key='synthetic-inline-key', label='kept-label'}]\n"
	redacted := Redact(raw)
	for _, secret := range []string{"synthetic-top-level-secret", "synthetic-nested-password", "synthetic-inline-key"} {
		if strings.Contains(redacted, secret) {
			t.Fatal("nested secret reached a configuration preview")
		}
	}
	if !strings.Contains(redacted, "kept-evidence") || !strings.Contains(redacted, "kept-label") {
		t.Fatal("non-sensitive unsupported evidence was lost")
	}
}
func TestScopedAdvancedOptionsSurviveAndSecurityOptionsDoNotDowngrade(t *testing.T) {
	s := fixture("backhaul")
	s.PeerOptions = map[string]map[string]any{"server": {"heartbeat": float64(30), "nodelay": true}, "client": {"retry_interval": float64(7), "connection_pool": float64(12), "nodelay": false}}
	server, e := Render(s, "server")
	if e != nil {
		t.Fatal(e)
	}
	client, e := Render(s, "client")
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct{ raw, role, key string }{{server, "server", "heartbeat"}, {client, "client", "retry_interval"}, {client, "client", "connection_pool"}} {
		parsed, _ := Parse(tc.raw)
		if _, ok := table(parsed, tc.role)[tc.key].(int64); !ok {
			t.Fatal("JSON roundtrip emitted TOML float", tc.key)
		}
	}
	s.RawServer = Redact(server)
	s.RawClient = Redact(client)
	if e = NormalizeRaw(&s); e != nil {
		t.Fatal(e)
	}
	again, _ := Render(s, "client")
	if !strings.Contains(again, "retry_interval = 7") || !strings.Contains(again, "nodelay = false") {
		t.Fatal("scoped options silently lost")
	}
	p, e := ParseConfiguration(server+"\n[server.proxy_identity]\nmode='mutual'\n", "backhaul")
	if e == nil && p.Reason == "" {
		t.Fatal("unsupported identity accepted")
	}
	p, e = ParseConfiguration(server+"\n[client]\nremote_addr='example.com:28100'\n", "backhaul")
	if e == nil && p.Reason == "" {
		t.Fatal("ambiguous dual role adopted")
	}
}

func TestRoundTripAndThreeIndependentEndpoints(t *testing.T) {
	for _, name := range []string{"backhaul"} {
		s := fixture(name)
		server, e := Render(s, "server")
		if e != nil {
			t.Fatal(e)
		}
		client, e := Render(s, "client")
		if e != nil {
			t.Fatal(e)
		}
		q := s
		q.RawServer = Redact(server)
		q.RawClient = Redact(client)
		if e = NormalizeRaw(&q); e != nil {
			t.Fatalf("%s %v", name, e)
		}
		if q.Routes[0].User.Port != 24443 || q.Routes[0].Backend.Port != 2096 || q.TransportBind.Port != 28100 || q.Token != s.Token {
			t.Fatal("endpoint or secret changed")
		}
		if strings.Contains(Redact(server), s.Token) || strings.Contains(Redact(client), s.Token) {
			t.Fatal("secret exposed")
		}
	}
}
func TestRawCannotBypassPreflightOrInjectPaths(t *testing.T) {
	s := fixture("backhaul")
	s.RawServer = "[server]\nbind_addr='0.0.0.0:28100'\ntransport='tcp'\ntoken='x'\nports=['24444=127.0.0.1:2096']\n"
	s.RawClient = "[client]\nremote_addr='listener.example.com:28100'\ntransport='tcp'\ntoken='x'\n"
	if e := NormalizeRaw(&s); e != nil {
		t.Fatal(e)
	}
	if s.Routes[0].User.Port != 24444 {
		t.Fatal("raw port not normalized")
	}
	s.RawServer = "[server]\ncommand='touch /tmp/unsafe'"
	if _, e := Render(s, "server"); e == nil {
		t.Fatal("invalid raw accepted")
	}
}
func TestConflictAndResourceBounds(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{{"0.0.0.0", "127.0.0.1", true}, {"::", "127.0.0.1", true}, {"127.0.0.1", "127.0.0.2", false}, {"::1", "0:0:0:0:0:0:0:1", true}}
	for _, c := range cases {
		if Conflict(Binding{c.a, 443, "tcp", ""}, Binding{c.b, 443, "tcp", ""}) != c.want {
			t.Fatal(c)
		}
	}
	s := fixture("backhaul")
	s.Advanced = map[string]any{"connection_pool": float64(1000000)}
	if Validate(s) == nil {
		t.Fatal("unbounded pool accepted")
	}
	s = fixture("backhaul")
	s.Routes = append(s.Routes, s.Routes[0])
	if Validate(s) == nil {
		t.Fatal("duplicate route accepted")
	}
	s = fixture("backhaul")
	s.Transport = "wss"
	s.Certificate = "test"
	if Validate(s) == nil {
		t.Fatal("unverified peer silently accepted")
	}
}
func TestSharedTokenMaskAndUnsupportedEngine(t *testing.T) {
	s := fixture("backhaul")
	s.Token = ""
	if e := GenerateSecrets(&s); e != nil {
		t.Fatal(e)
	}
	raw, e := Render(s, "server")
	if e != nil {
		t.Fatal(e)
	}
	public := Public(s)
	if public.Token != Mask || strings.Contains(Redact(raw), s.Token) {
		t.Fatal("shared token exposed")
	}
	next := public
	MergeSecrets(&next, s)
	if next.Token != s.Token {
		t.Fatal("masked edit lost token")
	}
	s.Engine = "unknown_engine"
	if Validate(s) == nil {
		t.Fatal("unsupported engine accepted")
	}
	if _, e = ParseConfiguration(raw, "unknown_engine"); e == nil {
		t.Fatal("unsupported parser accepted")
	}
}
