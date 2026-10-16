package engine

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

type Parsed struct {
	Options   map[string]any `json:"options,omitempty"`
	Role      string         `json:"role"`
	Transport string         `json:"transport"`
	Bind      string         `json:"bind"`
	Remote    string         `json:"remote"`
	Routes    []Route        `json:"routes"`
	Token     string         `json:"-"`
	Reason    string         `json:"reason,omitempty"`
}

func text(m map[string]any, k string) string          { s, _ := m[k].(string); return s }
func table(m map[string]any, k string) map[string]any { v, _ := m[k].(map[string]any); return v }
func ParseConfiguration(raw, name string) (Parsed, error) {
	m, e := Parse(raw)
	if e != nil {
		return Parsed{}, e
	}
	role := "server"
	side := table(m, role)
	if side == nil {
		role = "client"
		side = table(m, role)
	}
	if side == nil {
		return Parsed{}, errors.New("no server/client configuration found")
	}
	if table(m, "server") != nil && table(m, "client") != nil {
		return Parsed{}, errors.New("both roles require explicit native role selection")
	}
	p := Parsed{Role: role, Bind: text(side, "bind_addr"), Remote: text(side, "remote_addr"), Routes: []Route{}}
	if opts, e := Options(name, side); e != nil {
		p.Reason = e.Error()
	} else {
		p.Options = opts
	}
	if name == "backhaul" {
		p.Transport = text(side, "transport")
		p.Token = text(side, "token")
		if ports, ok := side["ports"].([]any); ok {
			for n, v := range ports {
				s, ok := v.(string)
				if !ok {
					p.Reason = "invalid port mapping"
					continue
				}
				routes, e := parseBackhaulMapping(s, n)
				if e != nil {
					p.Reason = "advanced/range mapping requires explicit normalized import"
					continue
				}
				p.Routes = append(p.Routes, routes...)
			}
		}
	} else {
		p.Token = text(side, "default_token")
		p.Transport = text(table(side, "transport"), "type")
		if p.Transport == "" {
			p.Transport = "tcp"
		}
		services := table(side, "services")
		keys := []string{}
		for key := range services {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			v := table(services, key)
			r := Route{ID: key, Name: key, Protocol: text(v, "type")}
			if r.Protocol == "" {
				r.Protocol = "tcp"
			}
			if role == "server" {
				r.User, e = ParseEndpoint(text(v, "bind_addr"))
			} else {
				r.Backend, e = ParseEndpoint(text(v, "local_addr"))
			}
			if e != nil {
				p.Reason = "invalid service endpoint"
				continue
			}
			p.Routes = append(p.Routes, r)
		}
	}
	if len(p.Routes) > 200 {
		p.Routes = p.Routes[:200]
		p.Reason = "route list limited to 200"
	}
	return p, nil
}
func parseBackhaulMapping(s string, n int) ([]Route, error) {
	left, right, has := strings.Cut(s, "=")
	if !has {
		left, right, has = strings.Cut(s, ":")
		if !has {
			left = s
			right = s
		} else if net.ParseIP(left) != nil || strings.Contains(s, "]") {
			return nil, errors.New("ambiguous mapping")
		}
	}
	if strings.Contains(left, "-") {
		return nil, errors.New("range mapping")
	}
	if !strings.Contains(left, ":") {
		left = net.JoinHostPort("0.0.0.0", left)
	}
	if !strings.Contains(right, ":") {
		if _, e := strconv.Atoi(right); e != nil {
			return nil, e
		}
		right = net.JoinHostPort("127.0.0.1", right)
	}
	u, e := ParseEndpoint(left)
	if e != nil {
		return nil, e
	}
	b, e := ParseEndpoint(right)
	if e != nil {
		return nil, e
	}
	return []Route{{ID: fmt.Sprintf("route_%d", n+1), Name: fmt.Sprintf("Port %d", u.Port), User: u, Backend: b, Protocol: "tcp"}}, nil
}
