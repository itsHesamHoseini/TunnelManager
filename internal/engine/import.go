package engine

import "errors"

// Read only the secrets needed by already selected routes. Imported configs are
// retained on the node; the controller stores this value only in AEAD ciphertext.
func ImportSecrets(s *Spec, serverRaw, clientRaw string) error {
	if s.Engine != "backhaul" {
		return errors.New("unsupported_engine")
	}
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

	s.Token = text(server, "token")
	if s.Token != text(client, "token") {
		return errors.New("peer_tokens_disagree")
	}

	return nil
}
