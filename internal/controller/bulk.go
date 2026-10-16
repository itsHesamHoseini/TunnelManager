package controller

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
)

func (s *Server) bulkTunnelAction(w http.ResponseWriter, r *http.Request) {
	var input struct {
		RequestKey, Action string
		Revisions          map[string]int64
		Confirm            bool
	}
	if !decode(w, r, &input) {
		return
	}
	if !input.Confirm || len(input.Revisions) < 1 || len(input.Revisions) > 50 || !strings.Contains("|start|stop|restart|disable|", "|"+input.Action+"|") {
		badOperation(w, errors.New("review_bulk_action_and_routes"))
		return
	}
	var combined JobPayload
	parts := map[string]ChangePart{}
	updates := map[string]TunnelUpdate{}
	ids := []string{}
	for id := range input.Revisions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		rec, rev, managed, e := s.readTunnel(r.Context(), id)
		if e != nil || !managed || rev != input.Revisions[id] {
			badOperation(w, errors.New("tunnel_revision_changed"))
			return
		}
		q := JobPayload{Tunnel: id, Spec: rec.Spec, Instances: rec.Instances, Hashes: rec.Hashes, ExpectedRevision: rev, Action: input.Action, Confirm: true}
		s.DB.QueryRow(r.Context(), "SELECT name FROM tunnels WHERE id=$1", id).Scan(&q.Name)
		if e = s.expand(r.Context(), &q); e != nil {
			badOperation(w, e)
			return
		}
		if combined.Tunnel == "" {
			combined = q
		}
		for _, p := range q.Parts {
			parts[p.Node+":"+p.Instance] = p
		}
		for _, g := range q.Updates {
			updates[g.ID] = g
		}
	}
	combined.Parts = nil
	combined.Updates = nil
	for _, p := range parts {
		combined.Parts = append(combined.Parts, p)
	}
	for _, g := range updates {
		combined.Updates = append(combined.Updates, g)
	}
	// Stable ordering makes duplicate request validation independent of map iteration.
	sort.Slice(combined.Parts, func(i, j int) bool {
		return combined.Parts[i].Node+combined.Parts[i].Instance < combined.Parts[j].Node+combined.Parts[j].Instance
	})
	sort.Slice(combined.Updates, func(i, j int) bool { return combined.Updates[i].ID < combined.Updates[j].ID })
	b, _ := json.Marshal(input)
	combined.RequestHash = string(b)
	id, e := s.newJob(r.Context(), input.RequestKey, "tunnel-action", combined.Tunnel, "Bulk "+input.Action, combined)
	if e != nil {
		badOperation(w, e)
		return
	}
	write(w, map[string]any{"operation_id": id, "affected_tunnels": publicAffected(combined)})
}
