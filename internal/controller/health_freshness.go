package controller

import (
	"context"
	"encoding/json"
	"time"
)

func (s *Server) currentHealth(ctx context.Context, raw []byte, rec TunnelRecord) any {
	var health map[string]any
	json.Unmarshal(raw, &health)
	if health == nil {
		health = map[string]any{}
	}
	for node := range rec.Instances {
		var seen *time.Time
		s.DB.QueryRow(ctx, "SELECT seen FROM nodes WHERE id=$1", node).Scan(&seen)
		if seen == nil || time.Since(*seen) > 90*time.Second || !s.isConnected(node) {
			health["stale"] = true
			health["freshness_reason"] = "node_offline_or_observation_stale"
			break
		}
	}
	return health
}

func (s *Server) invalidateHealth(ctx context.Context, node, instance, reason string) {
	for _, t := range s.affected(ctx, node, instance) {
		s.DB.Exec(ctx, `UPDATE tunnels SET health=jsonb_build_object('process','[]'::jsonb,'transport',jsonb_build_object('status','unknown','code',$1::text),'application',jsonb_build_object('status','unknown')) WHERE id=$2`, reason, t["id"])
	}
}
