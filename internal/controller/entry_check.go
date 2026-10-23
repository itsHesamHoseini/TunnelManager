package controller

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/itsHesamHoseini/TunnelManager/internal/engine"
	"github.com/itsHesamHoseini/TunnelManager/internal/nodeops"
	"net/http"
	"time"
)

func entryTarget(spec engine.Spec, mapping string) (string, engine.Endpoint, error) {
	for _, route := range spec.Routes {
		if route.ID == mapping {
			endpoint := route.User
			origin := spec.Dialer
			switch endpoint.Host {
			case "0.0.0.0", "::", "*", "":
				endpoint.Host = spec.TransportRemote.Host
			case "127.0.0.1", "::1", "localhost":
				origin = spec.Listener
			}
			if !engine.ValidHost(endpoint.Host) || endpoint.Port < 1 || endpoint.Port > 65535 {
				return "", endpoint, errors.New("invalid_diagnostic_target")
			}
			return origin, endpoint, nil
		}
	}
	return "", engine.Endpoint{}, errors.New("mapping_not_found")
}
func (s *Server) entryCheck(w http.ResponseWriter, r *http.Request) {
	var input struct {
		RequestKey, Mapping, Kind, ServerName string
		ExpectedRevision                      int64
	}
	if !decode(w, r, &input) {
		return
	}
	if input.Kind != "tcp" && input.Kind != "tls" || input.ServerName != "" && !engine.ValidHost(input.ServerName) {
		badOperation(w, errors.New("unsupported_entry_check"))
		return
	}
	record, revision, _, err := s.readTunnel(r.Context(), r.PathValue("id"))
	if err != nil || revision != input.ExpectedRevision {
		badOperation(w, errors.New("tunnel_revision_changed"))
		return
	}
	source, target, err := entryTarget(record.Spec, input.Mapping)
	if err != nil {
		badOperation(w, err)
		return
	}
	diagnostic, _ := json.Marshal(nodeops.Diagnostic{Kind: input.Kind, Endpoint: target, ServerName: input.ServerName})
	id, err := s.newJob(r.Context(), input.RequestKey, "entry-check", r.PathValue("id"), "Check user entry", JobPayload{Tunnel: r.PathValue("id"), ExpectedRevision: revision, Node: source, Payload: diagnostic})
	if err != nil {
		badOperation(w, err)
		return
	}
	write(w, map[string]string{"operation_id": id})
}
func (s *Server) processEntryCheck(ctx context.Context, id string, q JobPayload) {
	_, revision, _, err := s.readTunnel(ctx, q.Tunnel)
	if err != nil || revision != q.ExpectedRevision {
		s.phase(ctx, id, "failed", nil, errors.New("tunnel_revision_changed"))
		return
	}
	s.phase(ctx, id, "running", nil, nil)
	s.step(ctx, id, "entry-check", q.Node, "running", "")
	result, err := s.command(ctx, id, q.Node, "entry-check", "diagnostic", q.Payload)
	if err != nil {
		s.step(ctx, id, "entry-check", q.Node, "failed", err.Error())
		s.phase(ctx, id, "failed", nil, err)
		return
	}
	var observed map[string]any
	if json.Unmarshal(result.Data, &observed) != nil {
		s.phase(ctx, id, "failed", nil, errors.New("invalid_result"))
		return
	}
	observed["source"] = q.Node
	observed["entry_check"] = true
	observed["scope"] = "selected user entry through tunnel; TCP/TLS only, not VLESS proof"
	var expires time.Time
	if s.DB.QueryRow(ctx, "SELECT expires FROM commands WHERE operation_id=$1 AND node_id=$2 AND stage='entry-check'", id, q.Node).Scan(&expires) != nil || time.Now().After(expires) {
		s.phase(ctx, id, "failed", nil, errors.New("observation_stale"))
		return
	}
	raw, _ := json.Marshal(observed)
	if _, err = s.DB.Exec(ctx, "INSERT INTO checks(node_id,target,kind,data)VALUES($1,$2,'entry',$3)", q.Node, q.Tunnel, raw); err != nil {
		s.phase(ctx, id, "failed", nil, err)
		return
	}
	s.step(ctx, id, "entry-check", q.Node, "succeeded", "")
	s.phase(ctx, id, "succeeded", observed, nil)
}
