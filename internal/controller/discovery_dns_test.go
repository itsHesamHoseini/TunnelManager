package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/itsHesamHoseini/TunnelManager/internal/engine"
	"github.com/itsHesamHoseini/TunnelManager/internal/nodeops"
	"net"
	"strings"
	"testing"
	"time"
)

func TestDiscoveryResolverBounds(t *testing.T) {
	calls := 0
	r := newDiscoveryResolver(context.Background(), func(ctx context.Context, host string) ([]net.IPAddr, error) {
		calls++
		if host == "timeout.example.test" {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return []net.IPAddr{{IP: net.ParseIP("192.0.2.10")}}, nil
	})
	defer r.cancel()
	if !r.matches("peer.example.test", "192.0.2.10") || !r.matches("PEER.EXAMPLE.TEST.", "192.0.2.10") || calls != 1 {
		t.Fatal("DNS results not cached/canonicalized")
	}
	if r.matches("peer.example.test", "192.0.2.11") || r.matches("bad host", "192.0.2.10") || r.matches("peer.example.test", "127.0.0.1") || r.matches("0.0.0.0", "0.0.0.0") {
		t.Fatal("invalid evidence accepted")
	}
	if !r.matches("192.0.2.10", "192.0.2.10") || calls != 1 {
		t.Fatal("literal IP unnecessarily resolved")
	}
	start := time.Now()
	if r.matches("timeout.example.test", "192.0.2.10") || time.Since(start) > time.Second {
		t.Fatal("DNS timeout not bounded")
	}
	for i := 0; i < 30; i++ {
		r.matches(fmt.Sprintf("peer%d.example.test", i), "192.0.2.10")
	}
	if calls != 24 {
		t.Fatal("distinct query cap not respected", calls)
	}
}

func TestDNSDiscoveryOnlyCreatesUniqueObservation(t *testing.T) {
	for _, tc := range []struct {
		name                                string
		ambiguous, stale, mismatch, timeout bool
		want                                int
	}{
		{name: "unique", want: 1}, {name: "ambiguous", ambiguous: true}, {name: "stale", stale: true}, {name: "auth mismatch", mismatch: true}, {name: "DNS unavailable", timeout: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, srv, c := testServer(t)
			ctx := context.Background()
			server := nodeops.Discovered{Instance: nodeops.Instance{ID: "server-instance", Engine: "backhaul", Version: "0.7.2", Role: "server", Hash: "server-hash"}, Parsed: engine.Parsed{Role: "server", Transport: "tcp", Bind: "0.0.0.0:28100", Routes: []engine.Route{{ID: "route", User: engine.Endpoint{Host: "0.0.0.0", Port: 24443}, Backend: engine.Endpoint{Host: "127.0.0.1", Port: 2096}, Protocol: "tcp"}}}, AuthMatch: "private-match-material"}
			client := nodeops.Discovered{Instance: nodeops.Instance{ID: "client-instance", Engine: "backhaul", Version: "0.7.2", Role: "client", Hash: "client-hash"}, Parsed: engine.Parsed{Role: "client", Transport: "tcp", Remote: "peer.example.test:28100"}, AuthMatch: server.AuthMatch}
			if tc.mismatch {
				client.AuthMatch = "other-private-material"
			}
			server.Configuration = "[server]\nbind_addr='0.0.0.0:28100'\ntoken='synthetic-only-secret'\ncustom_observed_option=17\n"
			add := func(id string, d nodeops.Discovered, address string) {
				b, _ := json.Marshal(map[string]any{"instances": []nodeops.Discovered{d}, "addresses": []string{address}})
				_, e := s.DB.Exec(ctx, "INSERT INTO nodes(id,name,role,pubkey,approved,inventory_at,inventory)VALUES($1,$1,'foreign',$2,true,now(),$3)", id, make([]byte, 32), b)
				if e != nil {
					t.Fatal(e)
				}
			}
			add("server", server, "192.0.2.10")
			add("client", client, "192.0.2.20")
			if tc.ambiguous {
				add("other-server", server, "192.0.2.11")
			}
			if tc.stale {
				s.DB.Exec(ctx, "UPDATE nodes SET inventory_at=now()-interval '10 minutes' WHERE id='server'")
			}
			lookup := func(context.Context, string) ([]net.IPAddr, error) {
				if tc.timeout {
					return nil, errors.New("synthetic DNS unavailable")
				}
				return []net.IPAddr{{IP: net.ParseIP("192.0.2.10")}, {IP: net.ParseIP("192.0.2.11")}}, nil
			}
			s.reconcileDiscoveryWithLookup(ctx, lookup)
			s.reconcileDiscoveryWithLookup(ctx, lookup)
			var count, managed, commands int
			s.DB.QueryRow(ctx, "SELECT count(*),count(*)FILTER(WHERE managed) FROM tunnels").Scan(&count, &managed)
			s.DB.QueryRow(ctx, "SELECT count(*) FROM commands").Scan(&commands)
			if count != tc.want || managed != 0 || commands != 0 {
				t.Fatal("observation-only/unique constraint failed", count, managed, commands)
			}
			if count > 0 {
				var raw []byte
				s.DB.QueryRow(ctx, "SELECT health FROM tunnels LIMIT 1").Scan(&raw)
				if strings.Contains(string(raw), "passed") || strings.Contains(string(raw), "private-match") {
					t.Fatal("health inflated or matching material leaked")
				}
				// Unsupported render options still appear in read-only observed previews.
				var id string
				s.DB.QueryRow(ctx, "SELECT id FROM tunnels LIMIT 1").Scan(&id)
				enrollMFA(t, srv, c)
				status, detail := request(t, c, srv.URL+"/api/tunnels/"+id, "GET", nil)
				encoded, _ := json.Marshal(detail)
				if status != 200 || !strings.Contains(string(encoded), "custom_observed_option") || strings.Contains(string(encoded), "synthetic-only-secret") || strings.Contains(string(encoded), "private-match") {
					t.Fatal("observed configuration missing or secret exposed")
				}
				response, err := c.Get(srv.URL + "/api/discoveries")
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				var public any
				json.NewDecoder(response.Body).Decode(&public)
				encoded, _ = json.Marshal(public)
				if strings.Contains(string(encoded), "private-match") {
					t.Fatal("authentication evidence exposed")
				}

			}
		})
	}
}
