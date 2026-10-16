package controller

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sort"
	"time"

	"github.com/itsHesamHoseini/TunnelManager/internal/engine"
	"github.com/itsHesamHoseini/TunnelManager/internal/nodeops"
)

type discoveryNode struct {
	ID        string               `json:"id"`
	Name      string               `json:"name"`
	At        *time.Time           `json:"at"`
	Instances []nodeops.Discovered `json:"instances"`
	Addresses []string             `json:"-"`
}

func (s *Server) discoveries(ctx context.Context) ([]discoveryNode, error) {
	rows, e := s.DB.Query(ctx, "SELECT id,name,inventory_at,inventory FROM nodes WHERE approved ORDER BY name")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []discoveryNode{}
	for rows.Next() {
		var n discoveryNode
		var b []byte
		if rows.Scan(&n.ID, &n.Name, &n.At, &b) != nil {
			continue
		}
		var data struct {
			Instances []nodeops.Discovered `json:"instances"`
			Addresses []string             `json:"addresses"`
		}
		json.Unmarshal(b, &data)
		n.Instances = data.Instances
		n.Addresses = data.Addresses
		out = append(out, n)
	}
	return out, rows.Err()
}
func (s *Server) discoveryList(w http.ResponseWriter, r *http.Request) {
	nodes, e := s.discoveries(r.Context())
	if e != nil {
		badOperation(w, e)
		return
	}
	linked := map[string]bool{}
	rows, e := s.DB.Query(r.Context(), "SELECT id,cipher FROM tunnels")
	if e == nil {
		for rows.Next() {
			var id string
			var cipher []byte
			rows.Scan(&id, &cipher)
			var rec TunnelRecord
			if s.openValue("tunnel:"+id, cipher, &rec) == nil {
				for node, instance := range rec.Instances {
					linked[node+":"+instance] = true
				}
			}
		}
		rows.Close()
	}
	for i := range nodes {
		for j := range nodes[i].Instances {
			nodes[i].Instances[j].AuthMatch = ""
			nodes[i].Instances[j].Linked = linked[nodes[i].ID+":"+nodes[i].Instances[j].ID]
		}
	}
	write(w, nodes)
}
func findDiscovered(nodes []discoveryNode, node, id string) (nodeops.Discovered, error) {
	for _, n := range nodes {
		if n.ID == node {
			if n.At == nil || time.Since(*n.At) > 5*time.Minute {
				return nodeops.Discovered{}, errors.New("rediscover_before_import")
			}
			for _, d := range n.Instances {
				if d.ID == id {
					return d, nil
				}
			}
		}
	}
	return nodeops.Discovered{}, errors.New("discovered_instance_missing")
}
func pairedSpec(listener, dialer string, a, b nodeops.Discovered) (engine.Spec, error) {
	if a.Engine != b.Engine || a.Role != "server" || b.Role != "client" || a.Parsed.Transport != b.Parsed.Transport || listener == dialer {
		return engine.Spec{}, errors.New("select_corresponding_server_and_client")
	}
	bind, e := engine.ParseEndpoint(a.Parsed.Bind)
	if e != nil {
		return engine.Spec{}, e
	}
	remote, e := engine.ParseEndpoint(b.Parsed.Remote)
	if e != nil {
		return engine.Spec{}, e
	}
	if bind.Port != remote.Port {
		return engine.Spec{}, errors.New("transport_ports_disagree")
	}
	spec := engine.Spec{Engine: a.Engine, Version: a.Version, Transport: a.Parsed.Transport, Listener: listener, Dialer: dialer, TransportBind: bind, TransportRemote: remote, Routes: []engine.Route{}}
	spec.PeerOptions = map[string]map[string]any{"server": a.Parsed.Options, "client": b.Parsed.Options}
	if spec.Engine == "backhaul" {
		spec.Routes = a.Parsed.Routes
	} else {
		for _, ar := range a.Parsed.Routes {
			for _, br := range b.Parsed.Routes {
				if ar.ID == br.ID && ar.Protocol == br.Protocol {
					ar.Backend = br.Backend
					spec.Routes = append(spec.Routes, ar)
				}
			}
		}
	}
	if len(spec.Routes) == 0 {
		return spec, errors.New("no_corresponding_routes_select_manual_endpoints")
	}
	return spec, nil
}
func (s *Server) storeImport(ctx context.Context, name string, spec engine.Spec, a, b nodeops.Discovered, manual bool) (string, error) {
	rows, e := s.DB.Query(ctx, "SELECT id,cipher,revision,managed FROM tunnels")
	if e != nil {
		return "", e
	}
	existing := ""
	var existingRevision int64
	var existingManaged bool
	for rows.Next() {
		var id string
		var cipher []byte
		var rev int64
		var managed bool
		rows.Scan(&id, &cipher, &rev, &managed)
		var rec TunnelRecord
		if s.openValue("tunnel:"+id, cipher, &rec) == nil && rec.Instances[spec.Listener] == a.ID && rec.Instances[spec.Dialer] == b.ID {
			existing = id
			existingRevision = rev
			existingManaged = managed
			break
		}
	}
	rows.Close()
	if existing != "" && (!manual || existingManaged) {
		if manual && existingManaged {
			return "", errors.New("revoke_management_before_reimport")
		}
		return existing, nil
	}
	// Stable pair identity prevents a periodic discovery from duplicating imported paths.
	id := "import_" + engine.Digest([]byte(spec.Listener + ":" + a.ID + ":" + spec.Dialer + ":" + b.ID))[:24]
	record := TunnelRecord{Spec: spec, Instances: map[string]string{spec.Listener: a.ID, spec.Dialer: b.ID}, Hashes: map[string]string{spec.Listener: a.Hash, spec.Dialer: b.Hash}}
	if existing != "" {
		id = existing
	}
	cipher, e := s.sealValue("tunnel:"+id, record)
	if e != nil {
		return "", e
	}
	if existing != "" {
		tag, e := s.DB.Exec(ctx, "UPDATE tunnels SET name=$1,cipher=$2,revision=revision+1,health='{}',updated=now() WHERE id=$3 AND revision=$4 AND NOT managed", name, cipher, id, existingRevision)
		if e != nil {
			return "", e
		}
		if tag.RowsAffected() != 1 {
			return "", errors.New("tunnel_revision_changed")
		}
		return id, nil
	}
	health, _ := json.Marshal(map[string]any{"process": "unknown", "transport": "untested", "application": "unconfigured", "pairing": map[bool]string{true: "manual", false: "address, transport and authentication evidence"}[manual]})
	_, e = s.DB.Exec(ctx, "INSERT INTO tunnels(id,name,cipher,health)VALUES($1,$2,$3,$4) ON CONFLICT(id) DO NOTHING", id, name, cipher, health)
	return id, e
}
func (s *Server) reconcileDiscovery(ctx context.Context) {
	nodes, e := s.discoveries(ctx)
	if e != nil {
		return
	}
	for _, clientNode := range nodes {
		if clientNode.At == nil || time.Since(*clientNode.At) > 5*time.Minute {
			continue
		}
		for _, client := range clientNode.Instances {
			if client.Role != "client" || client.AuthMatch == "" || client.Managed {
				continue
			}
			remote, e := engine.ParseEndpoint(client.Parsed.Remote)
			if e != nil {
				continue
			}
			type match struct {
				node discoveryNode
				d    nodeops.Discovered
			}
			matches := []match{}
			for _, serverNode := range nodes {
				if serverNode.ID == clientNode.ID || serverNode.At == nil || time.Since(*serverNode.At) > 5*time.Minute {
					continue
				}
				addressMatches := false
				for _, a := range serverNode.Addresses {
					if net.ParseIP(a) != nil && net.ParseIP(a).Equal(net.ParseIP(remote.Host)) {
						addressMatches = true
					}
				}
				if !addressMatches {
					continue
				}
				for _, server := range serverNode.Instances {
					if server.Role != "server" || server.AuthMatch != client.AuthMatch || server.Managed {
						continue
					}
					if _, e := pairedSpec(serverNode.ID, clientNode.ID, server, client); e == nil {
						matches = append(matches, match{serverNode, server})
					}
				}
			}
			if len(matches) == 1 {
				m := matches[0]
				spec, e := pairedSpec(m.node.ID, clientNode.ID, m.d, client)
				if e == nil {
					s.storeImport(ctx, m.node.Name+" · "+clientNode.Name, spec, m.d, client, false)
				}
			}
		}
	}
}
func (s *Server) tunnelImport(w http.ResponseWriter, r *http.Request) {
	var q struct{ Name, Listener, Dialer, ServerInstance, ClientInstance string }
	if !decode(w, r, &q) {
		return
	}
	if len(q.Name) < 1 || len(q.Name) > 100 {
		badOperation(w, errors.New("tunnel_name_required"))
		return
	}
	nodes, e := s.discoveries(r.Context())
	if e != nil {
		badOperation(w, e)
		return
	}
	a, e := findDiscovered(nodes, q.Listener, q.ServerInstance)
	if e != nil {
		badOperation(w, e)
		return
	}
	b, e := findDiscovered(nodes, q.Dialer, q.ClientInstance)
	if e != nil {
		badOperation(w, e)
		return
	}
	spec, e := pairedSpec(q.Listener, q.Dialer, a, b)
	if e != nil {
		badOperation(w, e)
		return
	}
	id, e := s.storeImport(r.Context(), q.Name, spec, a, b, true)
	if e != nil {
		badOperation(w, e)
		return
	}
	s.Audit(r.Context(), "tunnel-import", q.Name, "metadata-only")
	write(w, map[string]any{"tunnel_id": id, "managed": false, "files_changed": false})
}
func (s *Server) tunnelAdopt(w http.ResponseWriter, r *http.Request) {
	var q struct {
		RequestKey       string
		ExpectedRevision int64
		Confirm          bool
	}
	if !decode(w, r, &q) {
		return
	}
	record, rev, managed, e := s.readTunnel(r.Context(), r.PathValue("id"))
	if e != nil || rev != q.ExpectedRevision || managed || !q.Confirm {
		badOperation(w, errors.New("review_import_and_explicitly_adopt"))
		return
	}
	id, e := s.newJob(r.Context(), q.RequestKey, "adopt", r.PathValue("id"), "Adopt existing instances", JobPayload{Tunnel: r.PathValue("id"), Spec: record.Spec, Instances: record.Instances, Hashes: record.Hashes, ExpectedRevision: rev, Confirm: true})
	if e != nil {
		badOperation(w, e)
		return
	}
	write(w, map[string]string{"operation_id": id})
}
func (s *Server) affected(ctx context.Context, node, instance string) []map[string]any {
	rows, e := s.DB.Query(ctx, "SELECT id,name,cipher,managed FROM tunnels")
	if e != nil {
		return nil
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, name string
		var cipher []byte
		var managed bool
		rows.Scan(&id, &name, &cipher, &managed)
		var rec TunnelRecord
		if s.openValue("tunnel:"+id, cipher, &rec) == nil && rec.Instances[node] == instance {
			out = append(out, map[string]any{"id": id, "name": name, "routes": engine.Public(rec.Spec).Routes, "managed": managed})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["name"].(string) < out[j]["name"].(string) })
	return out
}
func (s *Server) instanceAffected(w http.ResponseWriter, r *http.Request) {
	write(w, s.affected(r.Context(), r.PathValue("id"), r.PathValue("instance")))
}
