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

	s.Routes = retainMappingIdentity(s.Routes, sp.Routes)

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

// TOML has no panel IDs. First retain identities by the actual user binding;
// remaining replacements retain their row identity when that position is free.
// New rows get a binding-derived ID, avoiding a collision with a retained row.
func retainMappingIdentity(old, parsed []Route) []Route {
	used := map[int]bool{}
	matched := map[int]bool{}
	assign := func(i, j int) {
		parsed[i].ID = old[j].ID
		parsed[i].Name = old[j].Name
		used[j] = true
		matched[i] = true
	}
	for i, r := range parsed {
		for j, prior := range old {
			if !used[j] && prior.User == r.User {
				assign(i, j)
				break
			}
		}
	}
	for i := range parsed {
		if matched[i] {
			continue
		}
		if i < len(old) && !used[i] {
			assign(i, i)
		} else {
			parsed[i].ID = "raw_" + Digest([]byte(parsed[i].User.String()))[:16]
		}
	}
	return parsed
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
