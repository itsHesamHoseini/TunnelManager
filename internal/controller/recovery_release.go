package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/itsHesamHoseini/TunnelManager/internal/engine"
	"net/http"
)

func (s *Server) recoveryRelease(w http.ResponseWriter, r *http.Request) {
	var input struct{ Confirm bool }
	if !decode(w, r, &input) || !input.Confirm {
		badOperation(w, errors.New("explicit_recovery_release_required"))
		return
	}
	tx, e := s.DB.Begin(r.Context())
	if e != nil {
		badOperation(w, e)
		return
	}
	defer tx.Rollback(r.Context())
	var locked bool
	if tx.QueryRow(r.Context(), "SELECT pg_try_advisory_xact_lock(hashtext($1))", r.PathValue("id")).Scan(&locked) != nil || !locked {
		badOperation(w, errors.New("operation_busy_retry_after_current_step"))
		return
	}
	var kind, phase string
	var cipher []byte
	id := r.PathValue("id")
	if tx.QueryRow(r.Context(), "SELECT kind,phase,cipher FROM operations WHERE id=$1 FOR UPDATE", id).Scan(&kind, &phase, &cipher) != nil || phase != "needs_review" {
		badOperation(w, errors.New("review_failed_recovery_first"))
		return
	}
	var q JobPayload
	if s.openValue("operation:"+id, cipher, &q) != nil || (kind != "plan" && (kind != "certificate" || q.Kind != "deploy")) {
		badOperation(w, errors.New("recovery_release_not_available"))
		return
	}
	q.PreserveCurrent = true
	cipher, e = s.sealValue("operation:"+id, q)
	if e != nil {
		badOperation(w, e)
		return
	}
	if _, e = tx.Exec(r.Context(), "UPDATE operations SET cipher=$1,phase='release_pending',updated=now()-interval '31 seconds' WHERE id=$2", cipher, id); e != nil {
		badOperation(w, e)
		return
	}
	if kind == "certificate" {
		if _, e = tx.Exec(r.Context(), `UPDATE certificates SET metadata=metadata||jsonb_build_object('auto_deploy',false,'policy_revision',COALESCE((metadata->>'policy_revision')::bigint,0)+1) WHERE id=$1`, q.Certificate); e != nil {
			badOperation(w, e)
			return
		}
	}
	if e = tx.Commit(r.Context()); e != nil {
		badOperation(w, e)
		return
	}
	s.Audit(r.Context(), "recovery-release", id, "explicit-preserve-current-no-file-writes")
	write(w, map[string]bool{"accepted": true})
}
func (s *Server) processRecoveryRelease(ctx context.Context, id string, q JobPayload) {
	q.RecoveryAttempt++
	type target struct{ node, change, kind string }
	targets := []target{}
	for _, p := range q.Parts {
		targets = append(targets, target{p.Node, changeID(id, p.Instance), "config"})
	}
	if q.Certificate != "" {
		var list []CertificateDeployment
		if json.Unmarshal(q.Payload, &list) != nil {
			s.phase(ctx, id, "needs_review", nil, errors.New("invalid_certificate_targets"))
			return
		}
		for _, p := range list {
			targets = append(targets, target{p.Node, "cert_" + id, "certificate"})
		}
	}
	results := []any{}
	pending := false
	for _, p := range targets {
		s.step(ctx, id, "release_recovery", p.node, "running", "")
		_, e := s.command(ctx, id, p.node, fmt.Sprintf("release_%d_%s", q.RecoveryAttempt, engine.Digest([]byte(p.change))[:12]), "recovery.release", map[string]any{"ID": p.change, "Kind": p.kind, "Confirm": true})
		code := ""
		if e != nil {
			pending = true
			code = e.Error()
		}
		s.step(ctx, id, "release_recovery", p.node, map[bool]string{true: "succeeded", false: "failed"}[e == nil], code)
		results = append(results, map[string]any{"node": p.node, "released": e == nil, "code": code})
	}
	cipher, e := s.sealValue("operation:"+id, q)
	if e == nil {
		s.DB.Exec(ctx, "UPDATE operations SET cipher=$1 WHERE id=$2", cipher, id)
	}
	if pending {
		s.phase(ctx, id, "release_pending", map[string]any{"peers": results}, errors.New("waiting_to_release_peer_recovery"))
		return
	}
	conflicts := []string{}
	for _, g := range q.Updates {
		if g.Revision == 0 {
			continue
		}
		tag, e := s.DB.Exec(ctx, `UPDATE tunnels SET managed=false,revision=revision+1,health='{"transport":{"status":"unknown"},"application":{"status":"unknown"}}',updated=now() WHERE id=$1 AND revision=$2`, g.ID, g.Revision)
		if e != nil || tag.RowsAffected() == 0 {
			conflicts = append(conflicts, g.Name)
		}
	}
	if q.Certificate != "" {
		for _, p := range targets {
			var list []CertificateDeployment
			json.Unmarshal(q.Payload, &list)
			for _, t := range list {
				if t.Node == p.node {
					for _, instance := range t.Instances {
						s.invalidateHealth(ctx, p.node, instance, "certificate_rotation_requires_new_check")
					}
				}
			}
		}
	}
	s.phase(ctx, id, "released", map[string]any{"peers": results, "files_changed": false, "rollback_succeeded": false, "backups_preserved": true, "metadata_conflicts": conflicts, "next_action": "discover, compare and explicitly reimport/adopt current configurations"}, nil)
}
