package engine

import (
	"encoding/json"
	"fmt"
)

// Only documented scalar options are carried across form/raw/import round trips.
// Anything with unsupported identity, proxy or filesystem semantics stays read-only.
func Options(name string, side map[string]any) (map[string]any, error) {
	out := map[string]any{}
	for k, v := range side {
		switch k {
		case "bind_addr", "remote_addr", "token", "default_token", "ports":
			continue
		case "tls_cert", "tls_key":
			if name == "backhaul" {
				continue
			}
		case "transport":
			if name == "backhaul" {
				continue
			}
			m, _ := v.(map[string]any)
			options := map[string]any{}
			for key, value := range m {
				switch key {
				case "type":
					continue
				case "tcp":
					tcp, _ := value.(map[string]any)
					child := map[string]any{}
					for field, x := range tcp {
						if field == "nodelay" {
							if _, ok := x.(bool); !ok {
								return nil, fmt.Errorf("unsupported tcp option: %s", field)
							}
						} else if (field == "keepalive_secs" || field == "keepalive_interval") && numberRange(x, 0, 3600) {
						} else {
							return nil, fmt.Errorf("unsupported tcp option: %s", field)
						}
						child[field] = x
					}
					options[key] = child
				case "noise":
					n, _ := value.(map[string]any)
					for field, x := range n {
						if field == "pattern" {
							if x != "Noise_NK_25519_ChaChaPoly_BLAKE2s" {
								return nil, fmt.Errorf("unsupported Noise pattern")
							}
							continue
						}
						if field != "local_private_key" && field != "remote_public_key" {
							return nil, fmt.Errorf("unsupported Noise identity: %s", field)
						}
					}
				case "tls":
					n, _ := value.(map[string]any)
					for field := range n {
						if field != "pkcs12" && field != "pkcs12_password" && field != "trusted_root" && field != "hostname" {
							return nil, fmt.Errorf("unsupported TLS option: %s", field)
						}
					}
				default:
					return nil, fmt.Errorf("unsupported transport option: %s", key)
				}
			}
			if len(options) > 0 {
				out[k] = options
			}
			continue
		case "services":
			if name != "rathole" {
				return nil, fmt.Errorf("unsupported services table")
			}
			services, _ := v.(map[string]any)
			opts := map[string]any{}
			for id, value := range services {
				m, _ := value.(map[string]any)
				child := map[string]any{}
				for field, x := range m {
					switch field {
					case "type", "token", "bind_addr", "local_addr":
						continue
					case "nodelay":
						if _, ok := x.(bool); !ok {
							return nil, fmt.Errorf("invalid service nodelay")
						}
					case "retry_interval":
						if !numberRange(x, 1, 300) {
							return nil, fmt.Errorf("invalid service retry interval")
						}
					default:
						return nil, fmt.Errorf("unsupported service option: %s", field)
					}
					child[field] = x
				}
				if len(child) > 0 {
					opts[id] = child
				}
			}
			if len(opts) > 0 {
				out[k] = opts
			}
			continue
		case "heartbeat_interval", "heartbeat_timeout", "retry_interval":
			if name == "rathole" {
				if !numberRange(v, 1, 3600) {
					return nil, fmt.Errorf("invalid Rathole interval")
				}
				out[k] = v
				continue
			}
		case "log_level":
			if name == "backhaul" {
				switch v {
				case "trace", "debug", "info", "warn", "error", "fatal", "panic":
					out[k] = v
					continue
				}
			}
		case "web_port":
			if name == "backhaul" && numberRange(v, 0, 0) {
				continue
			}
		case "sniffer", "pprof", "accept_udp", "proxy_protocol":
			if name == "backhaul" && v == false {
				continue
			}
		case "sniffer_log", "edge_ip":
			if name == "backhaul" && v == "" {
				continue
			}
		case "skip_optz":
			if name == "backhaul" {
				if _, ok := v.(bool); ok {
					continue
				}
			}
		}
		b, _ := json.Marshal(v)
		var normalized any
		json.Unmarshal(b, &normalized)
		if !allowedAdvanced(name, k, normalized) {
			return nil, fmt.Errorf("unsupported engine option: %s", k)
		}
		out[k] = normalized
	}
	return out, nil
}
func numberRange(v any, min, max float64) bool {
	b, _ := json.Marshal(v)
	var n float64
	if json.Unmarshal(b, &n) != nil {
		return false
	}
	return n >= min && n <= max && n == float64(int64(n))
}
func mergeOptions(base, options map[string]any) {
	for k, v := range options {
		if child, ok := v.(map[string]any); ok {
			m, _ := base[k].(map[string]any)
			if m == nil {
				m = map[string]any{}
				base[k] = m
			}
			mergeOptions(m, child)
		} else {
			base[k] = v
		}
	}
}
