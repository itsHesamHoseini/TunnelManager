package controller

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/itsHesamHoseini/TunnelManager/internal/engine"
	"github.com/itsHesamHoseini/TunnelManager/internal/nodeops"
	"github.com/itsHesamHoseini/TunnelManager/internal/secure"
	"net/http"
	"strings"
	"time"
)

func supportReason(d nodeops.Discovered) string {
	if _, e := engine.ArtifactFor(d.Engine, d.Version, "amd64"); e != nil {
		return "unverified_version"
	}
	if d.Reason != "" || d.Parsed.Reason != "" {
		return "unsupported_configuration"
	}
	if d.Hash == "" || d.Fingerprint == "" || d.DefinitionHash == "" {
		return "missing_binary_or_unit_evidence"
	}
	if d.Role != "server" && d.Role != "client" {
		return "unknown_role"
	}
	if !strings.Contains("|tcp|tcpmux|ws|wss|wsmux|wssmux|", "|"+d.Parsed.Transport+"|") {
		return "unsupported_configuration"
	}
	for key := range d.Parsed.Options {
		valid := false
		for _, option := range engine.SupportedOptions {
			if option.Key == key {
				for _, role := range option.Roles {
					if role == d.Role {
						valid = true
					}
				}
			}
		}
		if !valid {
			return "unsupported_configuration"
		}
	}
	return ""
}
func adoptionEvidence(d nodeops.Discovered) string {
	return engine.Digest([]byte(strings.Join([]string{d.Hash, d.Fingerprint, d.DefinitionHash, d.Unit, d.Path, d.Binary}, "\x00")))
}

type adoptionItem struct {
	Node     string   `json:"node"`
	Server   string   `json:"server"`
	Instance string   `json:"instance"`
	Name     string   `json:"name"`
	Status   string   `json:"status"`
	Reason   string   `json:"reason"`
	Detail   string   `json:"detail,omitempty"`
	Version  string   `json:"version"`
	Role     string   `json:"role"`
	Tunnels  []string `json:"tunnels"`
}

func (s *Server) adoptionReport(w http.ResponseWriter, r *http.Request) {
	nodes, e := s.discoveries(r.Context())
	if e != nil {
		badOperation(w, e)
		return
	}
	type pair struct {
		id      string
		record  TunnelRecord
		managed bool
	}
	pairs := []pair{}
	byInstance := map[string][]int{}
	rows, e := s.DB.Query(r.Context(), "SELECT id,cipher,managed FROM tunnels")
	if e != nil {
		badOperation(w, e)
		return
	}
	for rows.Next() {
		var p pair
		var cipher []byte
		rows.Scan(&p.id, &cipher, &p.managed)
		if s.openValue("tunnel:"+p.id, cipher, &p.record) != nil || p.record.Spec.Engine != "backhaul" {
			continue
		}
		index := len(pairs)
		pairs = append(pairs, p)
		for node, id := range p.record.Instances {
			byInstance[node+":"+id] = append(byInstance[node+":"+id], index)
		}
	}
	rows.Close()
	discovered := map[string]nodeops.Discovered{}
	fresh := map[string]bool{}
	for _, n := range nodes {
		fresh[n.ID] = n.At != nil && time.Since(*n.At) >= 0 && time.Since(*n.At) < 5*time.Minute && s.isConnected(n.ID)
		for _, d := range n.Instances {
			discovered[n.ID+":"+d.ID] = d
		}
	}
	items := []adoptionItem{}
	counts := map[string]int{"managed": 0, "adoptable": 0, "readonly": 0, "unpaired": 0}
	for _, n := range nodes {
		for _, d := range n.Instances {
			item := adoptionItem{Node: n.ID, Server: n.Name, Instance: d.ID, Name: d.Name, Version: d.Version, Role: d.Role, Tunnels: []string{}, Status: "adoptable", Reason: "supported_pair"}
			links := byInstance[n.ID+":"+d.ID]
			managed := false
			reason := supportReason(d)
			for _, index := range links {
				p := pairs[index]
				item.Tunnels = append(item.Tunnels, p.id)
				managed = managed || p.managed
				for peer, instance := range p.record.Instances {
					other, found := discovered[peer+":"+instance]
					if !found {
						reason = "peer_missing"
						continue
					}
					if why := supportReason(other); why != "" {
						reason = why
					}
					if !fresh[peer] && reason == "" {
						reason = "rediscover_before_adoption"
					}
					if p.record.Hashes[peer] != "" && p.record.Hashes[peer] != other.Hash {
						reason = "configuration_drift"
					}
					if d.AuthMatch == "" || other.AuthMatch == "" {
						if reason == "" {
							reason = "authentication_unverified"
						}
					} else if d.AuthMatch != other.AuthMatch {
						reason = "authentication_mismatch"
					}
				}
			}
			if managed {
				item.Status = "managed"
				item.Reason = "explicitly_managed"
			} else if reason != "" {
				item.Status = "readonly"
				item.Reason = reason
				item.Detail = d.Reason
				if item.Detail == "" {
					item.Detail = d.Parsed.Reason
				}
			} else if len(links) == 0 {
				item.Status = "unpaired"
				item.Reason = "choose_peer"
			} else if !fresh[n.ID] {
				item.Status = "readonly"
				item.Reason = "rediscover_before_adoption"
			}
			counts[item.Status]++
			items = append(items, item)
		}
	}
	managedTunnels := 0
	for _, p := range pairs {
		if p.managed {
			managedTunnels++
		}
	}
	write(w, map[string]any{"items": items, "counts": counts, "scope": "discovered services; a shared service may belong to several tunnels", "managed_tunnels": managedTunnels, "observed_tunnels": len(pairs), "real_corpus_ratio": "unmeasured"})
}

func (s *Server) adoptionPreview(w http.ResponseWriter, r *http.Request) {
	var q struct {
		RequestKey       string
		ExpectedRevision int64
	}
	if !decode(w, r, &q) {
		return
	}
	record, rev, managed, e := s.readTunnel(r.Context(), r.PathValue("id"))
	if e != nil || managed || rev != q.ExpectedRevision {
		badOperation(w, errors.New("review_import_and_explicitly_adopt"))
		return
	}
	id, e := s.newJob(r.Context(), q.RequestKey, "adoption-preview", r.PathValue("id"), "Preview adoption", JobPayload{Tunnel: r.PathValue("id"), Spec: record.Spec, Instances: record.Instances, Hashes: record.Hashes, ExpectedRevision: rev})
	if e != nil {
		badOperation(w, e)
		return
	}
	write(w, map[string]string{"operation_id": id})
}

func (s *Server) readAdoptionEvidence(ctx context.Context, id string, q JobPayload) (map[string]nodeops.Discovered, error) {
	selected := map[string]nodeops.Discovered{}
	for _, p := range s.changeParts(q) {
		s.step(ctx, id, "preflight", p.Node, "running", "")
		if !s.isConnected(p.Node) {
			s.step(ctx, id, "preflight", p.Node, "failed", "node_offline")
			return selected, errors.New("node_offline")
		}
		var expired bool
		s.DB.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM commands WHERE operation_id=$1 AND node_id=$2 AND stage='adoption_inventory' AND expires<now())", id, p.Node).Scan(&expired)
		if expired {
			return selected, errors.New("repeat_adoption_preview")
		}
		match := secure.Hash(string(s.Config.Key) + "discovery-match-v1")
		v, e := s.command(ctx, id, p.Node, "adoption_inventory", "inventory", map[string]string{"MatchKey": base64.RawURLEncoding.EncodeToString([]byte(match)[:32])})
		if e != nil {
			s.step(ctx, id, "preflight", p.Node, "failed", e.Error())
			return selected, e
		}
		s.DB.Exec(ctx, "UPDATE nodes SET inventory=$1,inventory_at=(SELECT LEAST(created,now()) FROM commands WHERE operation_id=$3 AND node_id=$2 AND stage='adoption_inventory') WHERE id=$2", supportedInventory(v.Data), p.Node, id)
		var value struct {
			Instances []nodeops.Discovered `json:"instances"`
		}
		json.Unmarshal(v.Data, &value)
		var d *nodeops.Discovered
		for i := range value.Instances {
			if value.Instances[i].ID == q.Instances[p.Node] {
				d = &value.Instances[i]
				break
			}
		}
		code := ""
		if d == nil {
			code = "discovered_instance_missing"
		} else if d.Engine != "backhaul" || d.Role != p.Role {
			code = "select_corresponding_server_and_client"
		} else if supportReason(*d) != "" {
			code = supportReason(*d)
		} else if d.Hash != q.Hashes[p.Node] {
			code = "rediscover_and_import_changed_configuration_before_adoption"
		} else if expected := q.AdoptionEvidence[p.Node]; expected != "" && expected != adoptionEvidence(*d) {
			code = "discovery_drift"
		}
		if code != "" {
			s.step(ctx, id, "preflight", p.Node, "failed", code)
			return selected, errors.New(code)
		}
		selected[p.Node] = *d
		s.step(ctx, id, "preflight", p.Node, "succeeded", "")
	}
	a, b := selected[q.Spec.Listener], selected[q.Spec.Dialer]
	if a.AuthMatch == "" || b.AuthMatch == "" {
		return selected, errors.New("authentication_unverified")
	}
	if a.AuthMatch != b.AuthMatch {
		return selected, errors.New("authentication_mismatch")
	}
	return selected, nil
}

func (s *Server) processAdoptionPreview(ctx context.Context, id string, q JobPayload) {
	s.phase(ctx, id, "running", nil, nil)
	_, revision, managed, readError := s.readTunnel(ctx, q.Tunnel)
	if readError != nil || managed || revision != q.ExpectedRevision {
		s.phase(ctx, id, "failed", nil, errors.New("adoption_revision_changed"))
		return
	}
	selected, e := s.readAdoptionEvidence(ctx, id, q)
	if e != nil {
		s.phase(ctx, id, "failed", nil, e)
		return
	}
	q.AdoptionEvidence = map[string]string{}
	peers := []map[string]any{}
	for _, p := range s.changeParts(q) {
		d := selected[p.Node]
		q.AdoptionEvidence[p.Node] = adoptionEvidence(d)
		peers = append(peers, map[string]any{"node": p.Node, "role": p.Role, "unit": d.Unit, "path": d.Path, "version": d.Version})
	}
	cipher, e := s.sealValue("operation:"+id, q)
	if e != nil {
		s.phase(ctx, id, "failed", nil, e)
		return
	}
	if _, e = s.DB.Exec(ctx, "UPDATE operations SET cipher=$1 WHERE id=$2", cipher, id); e != nil {
		s.phase(ctx, id, "failed", nil, e)
		return
	}
	s.phase(ctx, id, "succeeded", map[string]any{"adoption_preview": true, "eligible": true, "peers": peers, "files_changed": false, "services_restarted": false}, nil)
}
