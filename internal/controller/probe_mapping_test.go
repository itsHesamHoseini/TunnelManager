package controller

import (
	"github.com/itsHesamHoseini/TunnelManager/internal/engine"
	"testing"
)

func TestMappingProbeFollowsSharedRestoreWithoutChangingCustomTarget(t *testing.T) {
	old := sharedSpec("client", "stable", 24443)
	old.Application = &engine.Probe{Kind: "http", Endpoint: engine.Endpoint{Host: old.TransportRemote.Host, Port: 24443}, Path: "/probe", Expected: "synthetic-expected"}
	next := old
	next.Routes = append([]engine.Route{}, old.Routes...)
	next.Routes[0].User.Port = 24444
	p, e := carryMappingProbe(old, next)
	if e != nil || p.Endpoint.Port != 24444 || old.Application.Endpoint.Port != 24443 {
		t.Fatal("tracked probe did not follow mapping or mutated prior config")
	}
	next.Application = &engine.Probe{Kind: "http", Endpoint: engine.Endpoint{Host: "custom.example.com", Port: 443}, Path: "/"}
	p, e = carryMappingProbe(old, next)
	if e != nil || p.Endpoint.Host != "custom.example.com" {
		t.Fatal("explicit custom probe overwritten")
	}
	next.Application = old.Application
	next.Routes = nil
	if _, e = carryMappingProbe(old, next); e == nil {
		t.Fatal("removed entry retained a misleading probe")
	}
}
