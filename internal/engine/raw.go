package engine

import (
	"errors"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// Raw changes are normalized into the exact same bounded model used by preflight.
// Engine filesystem paths and server/client agreement cannot escape that model.
func NormalizeRaw(s *Spec) error {
	if s.RawServer == "" && s.RawClient == "" {
		return nil
	}
	if s.RawServer == "" || s.RawClient == "" {
		return errors.New("raw editor requires both peer configurations")
	}
	sm, e := Parse(s.RawServer)
	if e != nil {
		return e
	}
	cm, e := Parse(s.RawClient)
	if e != nil {
		return e
	}
	server, client := table(sm, "server"), table(cm, "client")
	if len(sm) != 1 || len(cm) != 1 || server == nil || client == nil {
		return errors.New("raw configs must have one corresponding peer role each")
	}
	sp, e := ParseConfiguration(s.RawServer, s.Engine)
	if e != nil {
		return e
	}
	cp, e := ParseConfiguration(s.RawClient, s.Engine)
	if e != nil {
		return e
	}
	if sp.Reason != "" || cp.Reason != "" || sp.Transport != cp.Transport {
		return errors.New("raw peer transport or routes disagree")
	}
	keep := func(value, old string) string {
		if value == Mask {
			return old
		}
		return value
	}
	token := keep(sp.Token, s.Token)
	if keep(cp.Token, s.Token) != token {
		return errors.New("peer authentication tokens disagree")
	}
	s.Token = token
	s.Transport = sp.Transport
	s.TransportBind, e = ParseEndpoint(sp.Bind)
	if e != nil {
		return e
	}
	s.TransportRemote, e = ParseEndpoint(cp.Remote)
	if e != nil {
		return e
	}
	oldRoutes := map[string]Route{}
	for _, r := range s.Routes {
		oldRoutes[r.ID] = r
	}
	s.Routes = sp.Routes
	if s.Engine == "rathole" {
		if len(table(server, "services")) != len(table(client, "services")) {
			return errors.New("raw service names disagree")
		}
		for i := range s.Routes {
			c := table(table(client, "services"), s.Routes[i].ID)
			if c == nil {
				return errors.New("raw service missing on peer")
			}
			s.Routes[i].Backend, e = ParseEndpoint(text(c, "local_addr"))
			if e != nil {
				return e
			}
			if old, ok := oldRoutes[s.Routes[i].ID]; ok {
				s.Routes[i].Name = old.Name
			}
			old := oldRoutes[s.Routes[i].ID]
			st := keep(text(table(table(server, "services"), s.Routes[i].ID), "token"), old.Token)
			ct := keep(text(c, "token"), old.Token)
			if st != ct {
				return errors.New("route_authentication_tokens_disagree")
			}
			s.Routes[i].Token = st
		}
		st, ct := table(server, "transport"), table(client, "transport")
		if s.Transport == "noise" {
			s.NoisePrivate = keep(text(table(st, "noise"), "local_private_key"), s.NoisePrivate)
			if keep(text(table(ct, "noise"), "remote_public_key"), s.NoisePublic) != s.NoisePublic {
				return errors.New("Noise peer identity changed; use the explicit key rotation flow")
			}
		}
	}
	s.PeerOptions = map[string]map[string]any{}
	for role, side := range map[string]map[string]any{"server": server, "client": client} {
		opts, e := Options(s.Engine, side)
		if e != nil {
			return e
		}
		s.PeerOptions[role] = opts
	}
	s.Advanced = nil

	// Always re-render paths from an approved certificate ID; never honor arbitrary raw paths.
	s.RawServer = ""
	s.RawClient = ""
	return nil
}
func MergeRedactedRaw(next, old string) (string, error) {
	n, e := Parse(next)
	if e != nil {
		return "", e
	}
	o, e := Parse(old)
	if e != nil {
		return "", e
	}
	var merge func(map[string]any, map[string]any)
	merge = func(a, b map[string]any) {
		for k, v := range a {
			if text, ok := v.(string); ok && text == Mask {
				a[k] = b[k]
			}
			if child, ok := v.(map[string]any); ok {
				other, _ := b[k].(map[string]any)
				merge(child, other)
			}
		}
	}
	merge(n, o)
	b, e := toml.Marshal(n)
	return string(b), e
}
func RawHasSecrets(raw string) bool { return strings.Contains(raw, Mask) }
