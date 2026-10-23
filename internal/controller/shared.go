package controller

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/itsHesamHoseini/TunnelManager/internal/engine"
	"sort"
)

type ChangePart struct {
	Node, Role, Instance, Hash, NewHash string
	Spec                                engine.Spec
}
type TunnelUpdate struct {
	ID, Name string
	Revision int64
	Record   TunnelRecord
}

func changeID(op, instance string) string {
	return "chg_" + op + "_" + engine.Digest([]byte(instance))[:12]
}
func nodeSpec(p ChangePart) engine.Spec {
	spec := p.Spec
	spec.Application = nil
	if p.Role == "client" {
	}
	return spec
}

// Expand shared instances before preview. Render each server once with all of its
// routes; preserve each client's backend and update every shared revision/hash.
func (s *Server) expand(ctx context.Context, q *JobPayload) error {
	main := TunnelUpdate{ID: q.Tunnel, Name: q.Name, Revision: q.ExpectedRevision, Record: TunnelRecord{Spec: q.Spec, Instances: q.Instances, Hashes: q.Hashes}}
	group := []TunnelUpdate{main}
	if q.ExpectedRevision > 0 {
		rows, e := s.DB.Query(ctx, "SELECT id,name,revision,cipher,managed FROM tunnels WHERE id<>$1", q.Tunnel)
		if e != nil {
			return e
		}
		type other struct {
			TunnelUpdate
			managed bool
		}
		others := []other{}
		for rows.Next() {
			var v other
			var cipher []byte
			rows.Scan(&v.ID, &v.Name, &v.Revision, &cipher, &v.managed)
			if s.openValue("tunnel:"+v.ID, cipher, &v.Record) == nil {
				others = append(others, v)
			}
		}
		rows.Close()
		seen := map[string]bool{q.Tunnel: true}
		for changed := true; changed; {
			changed = false
			for _, v := range others {
				if seen[v.ID] {
					continue
				}
				matches := false
				for _, g := range group {
					for node, instance := range g.Record.Instances {
						if v.Record.Instances[node] == instance {
							matches = true
						}
					}
				}
				if matches {
					if !v.managed {
						return errors.New("adopt_all_shared_peers_before_coordinated_change")
					}
					group = append(group, v.TunnelUpdate)
					seen[v.ID] = true
					changed = true
				}
			}
		}
		old, _, _, e := s.readTunnel(ctx, q.Tunnel)
		if e != nil {
			return e
		}
		if len(group) > 1 && (q.Spec.Listener != old.Spec.Listener || q.Spec.Dialer != old.Spec.Dialer || q.Spec.Engine != old.Spec.Engine) {
			return errors.New("shared_peer_or_engine_replacement_requires_new_tunnel")
		}
		for i := 1; i < len(group); i++ {
			prior := group[i].Record.Spec
			next := q.Spec
			next.Listener = prior.Listener
			next.Dialer = prior.Dialer
			next.Application = prior.Application
			next.TransportRemote.Host = prior.TransportRemote.Host
			next.PeerOptions = sharedPeerOptions(prior, q.Spec)
			next.Routes = propagateSharedMappings(prior.Routes, old.Spec.Routes, q.Spec.Routes)
			var err error
			next.Application, err = carryMappingProbe(prior, next)
			if err != nil {
				return err
			}

			group[i].Record.Spec = next
		}
	}
	if len(group) > 20 {
		return errors.New("shared_group_exceeds_safe_operation_limit")
	}
	parts := map[string]*ChangePart{}
	for _, g := range group {
		for _, role := range []string{"server", "client"} {
			node := g.Record.Spec.Listener
			if role == "client" {
				node = g.Record.Spec.Dialer
			}
			instance := g.Record.Instances[node]
			k := node + ":" + instance
			if p := parts[k]; p != nil {
				if p.Role != role {
					return errors.New("shared_roles_disagree")
				}
				if p.Role == "server" {
					p.Spec.PeerOptions = sharedPeerOptions(g.Record.Spec, p.Spec)
				}
				for _, route := range g.Record.Spec.Routes {
					duplicate := false
					for _, existing := range p.Spec.Routes {
						if existing.ID == route.ID {
							a, _ := json.Marshal(existing)
							b, _ := json.Marshal(route)
							if string(a) != string(b) {
								return errors.New("shared_route_definitions_disagree")
							}
							duplicate = true
						}
					}
					if !duplicate {
						p.Spec.Routes = append(p.Spec.Routes, route)
					}
				}
			} else {
				spec := g.Record.Spec
				spec.Routes = append([]engine.Route{}, spec.Routes...)
				parts[k] = &ChangePart{Node: node, Role: role, Instance: instance, Hash: g.Record.Hashes[node], Spec: spec}
			}
		}
	}
	q.Parts = nil
	for _, p := range parts {
		if e := engine.Validate(p.Spec); e != nil && q.Action == "" {
			return e
		}
		q.Parts = append(q.Parts, *p)
	}
	sort.Slice(q.Parts, func(i, j int) bool {
		if q.Parts[i].Role != q.Parts[j].Role {
			return q.Parts[i].Role == "server"
		}
		return q.Parts[i].Node+q.Parts[i].Instance < q.Parts[j].Node+q.Parts[j].Instance
	})
	q.Updates = group
	return nil
}

// Backhaul's listener owns the mapping table. Preserve mappings outside the
// selected record, while propagating explicit edits/removals by stable route ID.
func propagateSharedMappings(prior, old, proposed []engine.Route) []engine.Route {
	was := map[string]bool{}
	next := map[string]engine.Route{}
	seen := map[string]bool{}
	for _, r := range old {
		was[r.ID] = true
	}
	for _, r := range proposed {
		next[r.ID] = r
	}
	out := []engine.Route{}
	for _, r := range prior {
		if replacement, ok := next[r.ID]; ok {
			r = replacement
		} else if was[r.ID] {
			continue
		}
		out = append(out, r)
		seen[r.ID] = true
	}
	for _, r := range proposed {
		if !seen[r.ID] {
			out = append(out, r)
		}
	}
	return out
}

func sharedPeerOptions(prior, requested engine.Spec) map[string]map[string]any {
	clone := func(value any) map[string]any {
		b, _ := json.Marshal(value)
		out := map[string]any{}
		json.Unmarshal(b, &out)
		if out == nil {
			out = map[string]any{}
		}
		return out
	}
	out := map[string]map[string]any{}
	server := clone(requested.PeerOptions["server"])
	services, _ := server["services"].(map[string]any)
	if services == nil {
		services = map[string]any{}
	}
	selected := map[string]bool{}
	for _, r := range requested.Routes {
		selected[r.ID] = true
	}
	oldServer := clone(prior.PeerOptions["server"])
	oldServices, _ := oldServer["services"].(map[string]any)
	for id, value := range oldServices {
		if !selected[id] {
			services[id] = value
		}
	}
	if len(services) > 0 {
		server["services"] = services
	}
	if len(server) > 0 {
		out["server"] = server
	}
	client := clone(prior.PeerOptions["client"])
	if len(client) > 0 {
		out["client"] = client
	}
	return out
}
func publicAffected(q JobPayload) []map[string]any {
	out := []map[string]any{}
	for _, g := range q.Updates {
		out = append(out, map[string]any{"id": g.ID, "revision": g.Revision, "name": g.Name, "routes": engine.Public(g.Record.Spec).Routes})
	}
	return out
}
