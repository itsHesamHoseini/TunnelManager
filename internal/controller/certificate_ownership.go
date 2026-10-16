package controller

import "context"

func (s *Server) freezeCertificateLinks(ctx context.Context, node, instance string) {
	s.DB.Exec(ctx, `UPDATE certificates SET metadata=metadata||jsonb_build_object('auto_deploy',false,'blocked_reason','consumer_management_revoked','policy_revision',COALESCE((metadata->>'policy_revision')::bigint,0)+1) WHERE id IN(SELECT certificate_id FROM certificate_links WHERE node_id=$1 AND instance_id=$2)`, node, instance)
}
