package engine

import (
	"strings"
	"testing"
)

func fixture(name string) Spec {
	return Spec{Engine: name, Version: map[string]string{"rathole": "0.5.0", "backhaul": "0.7.2"}[name], Transport: "tcp", Listener: "listener", Dialer: "dialer", TransportBind: Endpoint{"0.0.0.0", 28100}, TransportRemote: Endpoint{"listener.example.com", 28100}, Token: "synthetic-token-not-a-credential", Routes: []Route{{ID: "one", Name: "First", User: Endpoint{"0.0.0.0", 24443}, Backend: Endpoint{"127.0.0.1", 2096}, Protocol: "tcp"}}}
}
func TestScopedAdvancedOptionsSurviveAndSecurityOptionsDoNotDowngrade(t *testing.T) {
	s := fixture("rathole")
	s.PeerOptions = map[string]map[string]any{"server": {"heartbeat_interval": float64(30), "transport": map[string]any{"tcp": map[string]any{"nodelay": true}}}, "client": {"retry_interval": float64(7), "services": map[string]any{"one": map[string]any{"nodelay": false}}}}
	server, e := Render(s, "server")
	if e != nil {
		t.Fatal(e)
	}
	client, e := Render(s, "client")
	if e != nil {
		t.Fatal(e)
	}
	s.RawServer = Redact(server)
	s.RawClient = Redact(client)
	if e = NormalizeRaw(&s); e != nil {
		t.Fatal(e)
	}
	again, _ := Render(s, "client")
	if !strings.Contains(again, "retry_interval = 7") || !strings.Contains(again, "nodelay = false") {
		t.Fatal("scoped advanced options silently lost")
	}
	p, e := ParseConfiguration(server+"\n[server.transport.noise]\npattern='Noise_XX_25519_ChaChaPoly_BLAKE2s'\n", "rathole")
	if e == nil && p.Reason == "" {
		t.Fatal("unsupported mutual identity accepted for lossy conversion")
	}
	p, e = ParseConfiguration(server+"\n[client]\nremote_addr='example.com:28100'\n", "rathole")
	if e == nil && p.Reason == "" {
		t.Fatal("ambiguous dual role adopted")
	}
}
func TestRoundTripAndThreeIndependentEndpoints(t *testing.T) {
	for _, name := range []string{"backhaul", "rathole"} {
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
	s = fixture("rathole")
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
func TestNoiseIdentityAndRouteSecrets(t *testing.T) {
	s := fixture("rathole")
	s.Transport = "noise"
	if e := GenerateSecrets(&s); e != nil {
		t.Fatal(e)
	}
	s.Routes[0].Token = "synthetic-route-secret"
	raw, e := Render(s, "server")
	if e != nil {
		t.Fatal(e)
	}
	public := Public(s)
	if public.NoisePrivate != Mask || public.Routes[0].Token != Mask || strings.Contains(Redact(raw), "synthetic-route-secret") {
		t.Fatal("route/Noise secret exposed")
	}
	next := public
	MergeSecrets(&next, s)
	if next.NoisePrivate != s.NoisePrivate || next.Routes[0].Token != s.Routes[0].Token {
		t.Fatal("masked edit lost secrets")
	}
}
