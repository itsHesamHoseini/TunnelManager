package engine

import "errors"

// Read only the secrets needed by already selected routes. Imported configs are
// retained on the node; the controller stores this value only in AEAD ciphertext.
func ImportSecrets(s *Spec, serverRaw, clientRaw string) error {
	a, e := Parse(serverRaw)
	if e != nil {
		return e
	}
	b, e := Parse(clientRaw)
	if e != nil {
		return e
	}
	server, client := table(a, "server"), table(b, "client")
	if server == nil || client == nil {
		return errors.New("peer_roles_changed")
	}
	if s.Engine == "backhaul" {
		s.Token = text(server, "token")
		if s.Token != text(client, "token") {
			return errors.New("peer_tokens_disagree")
		}
	} else {
		s.Token = text(server, "default_token")
		if s.Token != text(client, "default_token") {
			return errors.New("peer_tokens_disagree")
		}
		if s.Token == "" {
			s.Token = "unused-global-token"
		}
		for i := range s.Routes {
			sid := s.Routes[i].ID
			st := text(table(table(server, "services"), sid), "token")
			ct := text(table(table(client, "services"), sid), "token")
			if st != ct {
				return errors.New("route_tokens_disagree")
			}
			s.Routes[i].Token = st
		}
		st, ct := table(server, "transport"), table(client, "transport")
		s.NoisePrivate = text(table(st, "noise"), "local_private_key")
		s.NoisePublic = text(table(ct, "noise"), "remote_public_key")
		s.PKCS12Password = text(table(st, "tls"), "pkcs12_password")
		s.TLSName = text(table(ct, "tls"), "hostname")
	}
	return nil
}
