package engine

import (
	"crypto/ecdh"
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

func (e Endpoint) String() string { return net.JoinHostPort(e.Host, strconv.Itoa(e.Port)) }

type Route struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	User     Endpoint `json:"user"`
	Backend  Endpoint `json:"backend"`
	Protocol string   `json:"protocol"`
	Token    string   `json:"token,omitempty"`
}
type Spec struct {
	Engine             string         `json:"engine"`
	Version            string         `json:"version"`
	Transport          string         `json:"transport"`
	Listener           string         `json:"listener"`
	Dialer             string         `json:"dialer"`
	TransportBind      Endpoint       `json:"transport_bind"`
	TransportRemote    Endpoint       `json:"transport_remote"`
	Routes             []Route        `json:"routes"`
	Token              string         `json:"token,omitempty"`
	NoisePrivate       string         `json:"noise_private,omitempty"`
	NoisePublic        string         `json:"noise_public,omitempty"`
	Certificate        string         `json:"certificate,omitempty"`
	TLSName            string         `json:"tls_name,omitempty"`
	PKCS12Password     string         `json:"pkcs12_password,omitempty"`
	Advanced           map[string]any `json:"advanced,omitempty"`
	AllowUnverifiedTLS bool           `json:"allow_unverified_tls"`
	RawServer          string         `json:"raw_server,omitempty"`
	RawClient          string         `json:"raw_client,omitempty"`
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
	{"rathole", "0.5.0", "amd64", "https://github.com/rathole-org/rathole/releases/download/v0.5.0/rathole-x86_64-unknown-linux-gnu.zip", "3e7d0d0f365120cd3cd351d147d1a12ee960c8068b464d4dd533a3821873b80e", "rathole", "Apache-2.0"},
	{"rathole", "0.5.0", "arm64", "https://github.com/rathole-org/rathole/releases/download/v0.5.0/rathole-aarch64-unknown-linux-musl.zip", "fa4a6fc63d86f8f1faa7c103a845e4715ce79a048455c0eec897b27237576564", "rathole", "Apache-2.0"},
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
	return e.Host != ""
}
func Validate(s Spec) error {
	if s.Engine != "backhaul" && s.Engine != "rathole" {
		return errors.New("select Backhaul or Rathole")
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
	if s.Engine == "backhaul" && !strings.Contains("|tcp|tcpmux|ws|wss|wsmux|wssmux|", "|"+s.Transport+"|") {
		return errors.New("unsupported Backhaul transport")
	}
	if s.Engine == "rathole" && !strings.Contains("|tcp|noise|tls|", "|"+s.Transport+"|") {
		return errors.New("unsupported Rathole transport")
	}
	if strings.HasPrefix(s.Transport, "wss") && !s.AllowUnverifiedTLS {
		return errors.New("this Backhaul version encrypts WSS but does not verify the peer certificate; explicit acknowledgement required")
	}
	if (strings.HasPrefix(s.Transport, "wss") || s.Transport == "tls") && !ID(s.Certificate) {
		return errors.New("select a deployed transport certificate")
	}
	if s.Engine == "rathole" && s.Transport == "noise" && (s.NoisePrivate == "" || s.NoisePublic == "") {
		return errors.New("Noise identity missing")
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
		if s.Engine == "backhaul" && r.Protocol != "tcp" {
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
	if s.Transport == "noise" && s.NoisePrivate == "" {
		k, e := ecdh.X25519().GenerateKey(rand.Reader)
		if e != nil {
			return e
		}
		s.NoisePrivate = base64.StdEncoding.EncodeToString(k.Bytes())
		s.NoisePublic = base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())
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
	if s.Engine == "backhaul" {
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
	} else {
		side["default_token"] = s.Token
		transport := map[string]any{"type": s.Transport}
		side["transport"] = transport
		if role == "server" {
			side["bind_addr"] = s.TransportBind.String()
		} else {
			side["remote_addr"] = s.TransportRemote.String()
		}
		if s.Transport == "noise" {
			n := map[string]any{}
			transport["noise"] = n
			if role == "server" {
				n["local_private_key"] = s.NoisePrivate
			} else {
				n["remote_public_key"] = s.NoisePublic
			}
		}
		if s.Transport == "tls" {
			t := map[string]any{}
			transport["tls"] = t
			if role == "server" {
				t["pkcs12"] = CertPath(s.Certificate, "identity.pfx")
				t["pkcs12_password"] = s.PKCS12Password
			} else {
				t["trusted_root"] = CertPath(s.Certificate, "cert.pem")
				t["hostname"] = s.TLSName
			}
		}
		services := map[string]any{}
		side["services"] = services
		for _, r := range s.Routes {
			v := map[string]any{"type": r.Protocol}
			if r.Token != "" {
				v["token"] = r.Token
			}
			if role == "server" {
				v["bind_addr"] = r.User.String()
			} else {
				v["local_addr"] = r.Backend.String()
			}
			services[r.ID] = v
		}
	}
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
	var walk func(map[string]any)
	walk = func(m map[string]any) {
		for k, v := range m {
			key := strings.ToLower(k)
			if strings.Contains(key, "token") || strings.Contains(key, "password") || strings.Contains(key, "private_key") || key == "proxy" {
				m[k] = Mask
			} else if child, ok := v.(map[string]any); ok {
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
	for i := range q.Routes {
		if q.Routes[i].Token != "" {
			q.Routes[i].Token = Mask
		}
	}
	if q.NoisePrivate != "" {
		q.NoisePrivate = Mask
	}
	if q.PKCS12Password != "" {
		q.PKCS12Password = Mask
	}
	if q.RawServer != "" {
		q.RawServer = Redact(q.RawServer)
	}
	if q.RawClient != "" {
		q.RawClient = Redact(q.RawClient)
	}
	return q
}
func MergeSecrets(next *Spec, old Spec) {
	for i := range next.Routes {
		for _, r := range old.Routes {
			if r.ID == next.Routes[i].ID && (next.Routes[i].Token == Mask || next.Routes[i].Token == "") {
				next.Routes[i].Token = r.Token
			}
		}
	}
	if next.Token == "" || next.Token == Mask {
		next.Token = old.Token
	}
	if next.NoisePrivate == "" || next.NoisePrivate == Mask {
		next.NoisePrivate = old.NoisePrivate
		next.NoisePublic = old.NoisePublic
	}
	if next.PKCS12Password == "" || next.PKCS12Password == Mask {
		next.PKCS12Password = old.PKCS12Password
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
