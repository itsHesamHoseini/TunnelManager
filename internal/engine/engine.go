package engine

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

const Mask = "[redacted]"

type Endpoint struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

func (e Endpoint) String() string {
	host := e.Host
	if host == "*" {
		host = "0.0.0.0"
	}
	return net.JoinHostPort(host, strconv.Itoa(e.Port))
}

type Route struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	User     Endpoint `json:"user"`
	Backend  Endpoint `json:"backend"`
	Protocol string   `json:"protocol"`
}
type Spec struct {
	Token               string                    `json:"token,omitempty"`
	PeerOptions         map[string]map[string]any `json:"peer_options,omitempty"`
	Application         *Probe                    `json:"application,omitempty"`
	Engine              string                    `json:"engine"`
	Version             string                    `json:"version"`
	Transport           string                    `json:"transport"`
	Listener            string                    `json:"listener"`
	Dialer              string                    `json:"dialer"`
	TransportBind       Endpoint                  `json:"transport_bind"`
	TransportRemote     Endpoint                  `json:"transport_remote"`
	Routes              []Route                   `json:"routes"`
	Certificate         string                    `json:"certificate,omitempty"`
	CertificateHash     string                    `json:"certificate_hash,omitempty"`
	CertificateRevision int64                     `json:"certificate_revision,omitempty"`
	TLSName             string                    `json:"tls_name,omitempty"`
	Advanced            map[string]any            `json:"advanced,omitempty"`
	AllowUnverifiedTLS  bool                      `json:"allow_unverified_tls"`
	RawServer           string                    `json:"raw_server,omitempty"`
	RawClient           string                    `json:"raw_client,omitempty"`
}
type Probe struct {
	Kind     string   `json:"kind"`
	Endpoint Endpoint `json:"endpoint"`
	Path     string   `json:"path"`
	Expected string   `json:"expected"`
}
type Binding struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Kind     string `json:"kind"`
}
type Artifact struct{ Engine, Version, Arch, URL, SHA256, Entry, License string }

var Catalog = []Artifact{
	{"backhaul", "0.7.2", "amd64", "https://github.com/Musixal/Backhaul/releases/download/v0.7.2/backhaul_linux_amd64.tar.gz", "57bf95c2eabeddb1152d2e94ac42f4310883ce0fb909ee2a57bd53503b2dabbc", "backhaul", "AGPL-3.0"},
	{"backhaul", "0.7.2", "arm64", "https://github.com/Musixal/Backhaul/releases/download/v0.7.2/backhaul_linux_arm64.tar.gz", "9a424c97ff16fc3f682e8314c418790d2b5bf3136e008edbb6cd402ea00999f6", "backhaul", "AGPL-3.0"},
}
var idPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

func ID(s string) bool { return idPattern.MatchString(s) }
func ArtifactFor(e, v, a string) (Artifact, error) {
	for _, x := range Catalog {
		if x.Engine == e && x.Version == v && x.Arch == a {
			return x, nil
		}
	}
	return Artifact{}, errors.New("unsupported engine version or architecture")
}
func Digest(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }
func ParseEndpoint(s string) (Endpoint, error) {
	h, p, e := net.SplitHostPort(s)
	if e != nil {
		return Endpoint{}, errors.New("use host:port (IPv6 in brackets)")
	}
	n, e := strconv.Atoi(p)
	if e != nil || n < 1 || n > 65535 {
		return Endpoint{}, errors.New("port must be 1..65535")
	}
	if h == "" {
		h = "0.0.0.0"
	}
	return Endpoint{h, n}, nil
}
func validEndpoint(e Endpoint, bind bool) bool {
	if e.Port < 1 || e.Port > 65535 || len(e.Host) > 253 || strings.ContainsAny(e.Host, "\r\n\x00 /\\\"'$") {
		return false
	}
	if bind {
		return e.Host == "*" || net.ParseIP(e.Host) != nil
	}
	return ValidHost(e.Host)
}
func ValidHost(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if host == "" || len(host) > 253 {
		return false
	}
	for _, part := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if len(part) < 1 || len(part) > 63 || part[0] == '-' || part[len(part)-1] == '-' {
			return false
		}
		for _, c := range part {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
func Validate(s Spec) error {
	if s.Engine != "backhaul" {
		return errors.New("unsupported_engine")
	}

	if _, e := ArtifactFor(s.Engine, s.Version, "amd64"); e != nil {
		return e
	}
	if s.Listener == s.Dialer || s.Listener == "" || s.Dialer == "" {
		return errors.New("select two different approved nodes")
	}
	if !validEndpoint(s.TransportBind, true) || !validEndpoint(s.TransportRemote, false) {
		return errors.New("invalid transport listener/dial endpoint")
	}
	if len(s.Token) < 1 || len(s.Token) > 512 {
		return errors.New("authentication token must be 1..512 characters; new tokens are generated securely")
	}
	if len(s.Routes) < 1 || len(s.Routes) > 200 {
		return errors.New("one to 200 routes required")
	}
	if !strings.Contains("|tcp|tcpmux|ws|wss|wsmux|wssmux|", "|"+s.Transport+"|") {
		return errors.New("unsupported Backhaul transport")
	}

	if strings.HasPrefix(s.Transport, "wss") && !s.AllowUnverifiedTLS {
		return errors.New("this Backhaul version encrypts WSS but does not verify the peer certificate; explicit acknowledgement required")
	}
	if strings.HasPrefix(s.Transport, "wss") && !ID(s.Certificate) {
		return errors.New("select a deployed transport certificate")
	}

	if p := s.Application; p != nil {
		if (p.Kind != "http" && p.Kind != "echo") || !validEndpoint(p.Endpoint, false) || len(p.Path) > 500 || len(p.Expected) > 128 || strings.ContainsAny(p.Path, "\r\n") {
			return errors.New("invalid_application_probe")
		}
	}
	seen := map[string]bool{}
	bindings := []Binding{}
	for _, r := range s.Routes {
		if !ID(r.ID) || seen[r.ID] || len(r.Name) > 100 || !validEndpoint(r.User, true) || !validEndpoint(r.Backend, false) {
			return errors.New("check route name, ID, user bind and backend endpoint")
		}
		seen[r.ID] = true
		if r.Protocol != "tcp" && r.Protocol != "udp" {
			return errors.New("route protocol must be tcp or udp")
		}
		if r.Protocol != "tcp" {
			return errors.New("this adapter requires explicit TCP routes; existing UDP configs stay read-only")
		}
		b := Binding{r.User.Host, r.User.Port, r.Protocol, "user"}
		for _, other := range bindings {
			if Conflict(b, other) {
				return errors.New("route user ports overlap")
			}
		}
		bindings = append(bindings, b)
		if r.Protocol == "tcp" && Conflict(b, Binding{s.TransportBind.Host, s.TransportBind.Port, "tcp", "transport"}) {
			return errors.New("user and transport listeners overlap")
		}
	}
	for k, v := range s.Advanced {
		if !allowedAdvanced(s.Engine, k, v) {
			return fmt.Errorf("unsupported or out-of-range advanced option: %s", k)
		}
	}
	for role, opts := range s.PeerOptions {
		if role != "server" && role != "client" {
			return errors.New("invalid option role")
		}
		if len(opts) == 0 {
			continue
		}
		normalized, e := Options(s.Engine, opts)
		if e != nil {
			return e
		}
		b, _ := json.Marshal(opts)
		c, _ := json.Marshal(normalized)
		if string(b) != string(c) {
			return errors.New("unsupported peer option")
		}
	}
	return nil
}
func allowedAdvanced(e, k string, v any) bool {
	if e == "backhaul" {
		switch k {
		case "nodelay", "aggressive_pool":
			_, ok := v.(bool)
			return ok
		case "connection_pool", "heartbeat", "keepalive_period", "retry_interval", "dial_timeout", "mux_con", "mux_version", "mux_framesize", "mux_recievebuffer", "mux_streambuffer", "channel_size":
			n, ok := v.(float64)
			limits := map[string]float64{"connection_pool": 256, "heartbeat": 300, "keepalive_period": 300, "retry_interval": 300, "dial_timeout": 60, "mux_con": 64, "mux_version": 2, "mux_framesize": 65535, "mux_recievebuffer": 16777216, "mux_streambuffer": 16777216, "channel_size": 4096}
			return ok && n >= 1 && n <= limits[k] && n == float64(int64(n))
		}
	}
	return false
}
func GenerateSecrets(s *Spec) error {
	if s.Token == "" {
		b := make([]byte, 32)
		if _, e := rand.Read(b); e != nil {
			return e
		}
		s.Token = base64.RawURLEncoding.EncodeToString(b)
	}

	return nil
}
func Conflict(a, b Binding) bool {
	if a.Port != b.Port || a.Protocol != b.Protocol {
		return false
	}
	wild := func(h string) bool { return h == "" || h == "*" || h == "0.0.0.0" || h == "::" }
	if wild(a.Host) || wild(b.Host) {
		return true
	}
	return net.ParseIP(a.Host).Equal(net.ParseIP(b.Host))
}
func Bindings(s Spec, role string) []Binding {
	if role != "server" {
		return nil
	}
	out := []Binding{{s.TransportBind.Host, s.TransportBind.Port, "tcp", "transport"}}
	for _, r := range s.Routes {
		out = append(out, Binding{r.User.Host, r.User.Port, r.Protocol, "user"})
	}
	return out
}
func Render(s Spec, role string) (string, error) {
	if e := NormalizeRaw(&s); e != nil {
		return "", e
	}
	if e := Validate(s); e != nil {
		return "", e
	}
	if role != "server" && role != "client" {
		return "", errors.New("role must be server/client")
	}

	cfg := map[string]any{}
	side := map[string]any{}
	cfg[role] = side

	side["transport"] = s.Transport
	side["token"] = s.Token
	side["log_level"] = "info"
	side["web_port"] = 0
	side["sniffer"] = false
	side["skip_optz"] = true
	if role == "server" {
		side["bind_addr"] = s.TransportBind.String()
		ports := []string{}
		for _, r := range s.Routes {
			ports = append(ports, r.User.String()+"="+r.Backend.String())
		}
		side["ports"] = ports
		if strings.HasPrefix(s.Transport, "wss") {
			side["tls_cert"] = CertPath(s.Certificate, "cert.pem")
			side["tls_key"] = CertPath(s.Certificate, "key.pem")
		}
	} else {
		side["remote_addr"] = s.TransportRemote.String()
		side["connection_pool"] = 8
		side["retry_interval"] = 3
	}
	for k, v := range s.Advanced {
		if role == "server" && (k == "connection_pool" || k == "aggressive_pool" || k == "dial_timeout" || k == "retry_interval") {
			continue
		}
		if role == "client" && (k == "heartbeat" || k == "channel_size" || k == "mux_con") {
			continue
		}
		side[k] = v
	}

	// Per-service options on another route must not synthesize a service without
	// its endpoint. Shared expansion renders those options with their own routes.
	encoded, _ := json.Marshal(s.PeerOptions[role])
	opts := map[string]any{}
	json.Unmarshal(encoded, &opts)
	if services, ok := opts["services"].(map[string]any); ok {
		valid := map[string]bool{}
		for _, route := range s.Routes {
			valid[route.ID] = true
		}
		for id := range services {
			if !valid[id] {
				delete(services, id)
			}
		}
	}
	mergeOptions(side, opts)
	tomlIntegerOptions(cfg)
	b, e := toml.Marshal(cfg)
	return string(b), e
}
func CertPath(id, file string) string {
	return "/etc/tunnelmanager-agent/certificates/" + id + "/" + file
}
func Parse(raw string) (map[string]any, error) {
	if len(raw) > 65536 {
		return nil, errors.New("configuration exceeds 64 KiB")
	}
	v := map[string]any{}
	if e := toml.Unmarshal([]byte(raw), &v); e != nil {
		return nil, errors.New("invalid TOML; check table names, quotes and values")
	}
	return v, nil
}
func ValidateRaw(raw, e, role string) (string, error) {
	v, err := Parse(raw)
	if err != nil {
		return "", err
	}
	if len(v) != 1 || v[role] == nil {
		return "", errors.New("configuration must contain only its selected engine role")
	}
	side, ok := v[role].(map[string]any)
	if !ok {
		return "", errors.New("invalid role table")
	}
	if e == "backhaul" {
		for k := range side {
			if k != "bind_addr" && k != "remote_addr" && k != "transport" && k != "token" && k != "ports" && k != "log_level" && k != "web_port" && k != "sniffer" && k != "skip_optz" && k != "tls_cert" && k != "tls_key" && !allowedAdvanced(e, k, side[k]) {
				return "", fmt.Errorf("unsupported Backhaul field: %s", k)
			}
		}
		if n, ok := side["web_port"].(int64); ok && n != 0 {
			return "", errors.New("engine web listeners must remain disabled")
		}
	}
	return raw, nil
}
func Redact(raw string) string {
	v, e := Parse(raw)
	if e != nil {
		return "[configuration unreadable]"
	}
	var walk func(any)
	walk = func(value any) {
		switch m := value.(type) {
		case map[string]any:
			for k, v := range m {
				key := strings.ToLower(k)
				if strings.Contains(key, "token") || strings.Contains(key, "password") || strings.Contains(key, "secret") || strings.Contains(key, "key") || key == "proxy" {
					m[k] = Mask
				} else {
					walk(v)
				}
			}
		case []any:
			for _, child := range m {
				walk(child)
			}
		}
	}
	walk(v)
	b, _ := toml.Marshal(v)
	return string(b)
}
func Public(s Spec) Spec {
	b, _ := json.Marshal(s)
	var q Spec
	json.Unmarshal(b, &q)
	q.Token = Mask
	if q.RawServer != "" {
		q.RawServer = Redact(q.RawServer)
	}
	if q.RawClient != "" {
		q.RawClient = Redact(q.RawClient)
	}
	return q
}
func MergeSecrets(next *Spec, old Spec) {
	if next.Token == "" || next.Token == Mask {
		next.Token = old.Token
	}
}

func SortedRouteIDs(s Spec) []string {
	out := []string{}
	for _, r := range s.Routes {
		out = append(out, r.ID)
	}
	sort.Strings(out)
	return out
}
