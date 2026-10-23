package controller

import (
	"encoding/json"
	"errors"
	"github.com/itsHesamHoseini/TunnelManager/internal/engine"
	"net/http"
	"reflect"
)

type SettingChange struct {
	Kind   string `json:"kind"`
	Route  string `json:"route,omitempty"`
	Before any    `json:"before,omitempty"`
	After  any    `json:"after,omitempty"`
}

// Secret values and arbitrary raw configuration never enter this public model.
func settingChanges(old *engine.Spec, next engine.Spec) []SettingChange {
	changes := []SettingChange{}
	add := func(kind, route string, before, after any) {
		if !reflect.DeepEqual(before, after) {
			changes = append(changes, SettingChange{kind, route, before, after})
		}
	}
	if old == nil {
		changes = append(changes, SettingChange{Kind: "create"})
	} else {
		add("entry_server", "", old.Listener, next.Listener)
		add("destination_server", "", old.Dialer, next.Dialer)
		add("transport_port", "", old.TransportBind.Port, next.TransportBind.Port)
		add("connection_address", "", old.TransportRemote, next.TransportRemote)
		add("listen_address", "", old.TransportBind.Host, next.TransportBind.Host)
		add("transport", "", old.Transport, next.Transport)
		add("version", "", old.Version, next.Version)
		add("certificate", "", old.Certificate, next.Certificate)
		add("certificate_name", "", old.TLSName, next.TLSName)
		if old.Token != next.Token {
			changes = append(changes, SettingChange{Kind: "token_changed"})
		}
		a, b := struct{ Advanced, Peers any }{old.Advanced, old.PeerOptions}, struct{ Advanced, Peers any }{next.Advanced, next.PeerOptions}
		x, _ := json.Marshal(a)
		y, _ := json.Marshal(b)
		if string(x) != string(y) {
			changes = append(changes, SettingChange{Kind: "advanced_changed"})
		}
		if !reflect.DeepEqual(old.Application, next.Application) {
			changes = append(changes, SettingChange{Kind: "probe"})
		}
	}
	previous := map[string]engine.Route{}
	if old != nil {
		for _, r := range old.Routes {
			previous[r.ID] = r
		}
	}
	for _, route := range next.Routes {
		prior, found := previous[route.ID]
		name := route.Name
		if name == "" {
			name = route.ID
		}
		if !found {
			changes = append(changes, SettingChange{Kind: "mapping_added", Route: name, After: route})
			continue
		}
		add("user_port", name, prior.User.Port, route.User.Port)
		add("user_address", name, prior.User.Host, route.User.Host)
		add("backend", name, prior.Backend, route.Backend)
		add("mapping_name", name, prior.Name, route.Name)
		delete(previous, route.ID)
	}
	if old != nil {
		for _, route := range old.Routes {
			if _, ok := previous[route.ID]; ok {
				changes = append(changes, SettingChange{Kind: "mapping_removed", Route: route.Name, Before: route})
			}
		}
	}
	return changes
}

func (s *Server) backhaulOptions(w http.ResponseWriter, r *http.Request) {
	write(w, engine.SupportedOptions)
}

// This endpoint normalizes a draft without persisting or contacting any node.
// Secret merge and revision checks are identical to the durable plan path.
func (s *Server) normalizeDraft(w http.ResponseWriter, r *http.Request) {
	var q struct {
		Tunnel           string
		ExpectedRevision int64
		Spec             engine.Spec
	}
	if !decode(w, r, &q) {
		return
	}
	if q.Tunnel != "" {
		old, rev, managed, e := s.readTunnel(r.Context(), q.Tunnel)
		if e != nil || rev != q.ExpectedRevision {
			badOperation(w, errors.New("tunnel_revision_changed"))
			return
		}
		if !managed {
			badOperation(w, errors.New("explicit_adoption_required"))
			return
		}
		engine.MergeSecrets(&q.Spec, old.Spec)
	}
	if e := engine.NormalizeRaw(&q.Spec); e != nil {
		badOperation(w, e)
		return
	}
	if q.Spec.Token == engine.Mask {
		q.Spec.Token = ""
	}
	if e := engine.GenerateSecrets(&q.Spec); e != nil {
		badOperation(w, e)
		return
	}
	configurations := map[string]string{}
	for _, role := range []string{"server", "client"} {
		raw, e := engine.Render(q.Spec, role)
		if e != nil {
			badOperation(w, e)
			return
		}
		configurations[role] = engine.Redact(raw)
	}
	write(w, map[string]any{"spec": engine.Public(q.Spec), "configurations": configurations})
}
