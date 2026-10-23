package engine

import "testing"

func TestRawRoundTripKeepsMappingIdentityAndNames(t *testing.T) {
	s := fixture("backhaul")
	s.Routes[0].ID = "custom_stable_id"
	s.Routes[0].Name = "Custom friendly name"
	server, _ := Render(s, "server")
	client, _ := Render(s, "client")
	s.RawServer = Redact(server)
	s.RawClient = Redact(client)
	if e := NormalizeRaw(&s); e != nil {
		t.Fatal(e)
	}
	if s.Routes[0].ID != "custom_stable_id" || s.Routes[0].Name != "Custom friendly name" {
		t.Fatal("raw round trip lost mapping identity or name")
	}
}
