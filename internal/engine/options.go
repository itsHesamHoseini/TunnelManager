package engine

import (
	"encoding/json"
	"fmt"
)

// Only documented scalar options are carried across form/raw/import round trips.
// Anything with unsupported identity, proxy or filesystem semantics stays read-only.
func Options(name string, side map[string]any) (map[string]any, error) {
	if name != "backhaul" {
		return nil, fmt.Errorf("unsupported_engine")
	}
	out := map[string]any{}
	for k, v := range side {
		switch k {
		case "bind_addr", "remote_addr", "token", "ports", "tls_cert", "tls_key", "transport":
			continue
		case "log_level":
			switch v {
			case "trace", "debug", "info", "warn", "error", "fatal", "panic":
				out[k] = v
				continue
			}
		case "web_port":
			if numberRange(v, 0, 0) {
				continue
			}
		case "sniffer", "pprof", "accept_udp", "proxy_protocol":
			if v == false {
				continue
			}
		case "sniffer_log", "edge_ip":
			if v == "" {
				continue
			}
		case "skip_optz":
			if _, ok := v.(bool); ok {
				out[k] = v
				continue
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

// JSON decodes validated integer engine options as float64. TOML distinguishes
// integers from floats, and the native engines reject e.g. retry_interval=2.0.
// Run only on the newly rendered map, never on the caller's draft/options.
func tomlIntegerOptions(m map[string]any) {
	for key, value := range m {
		switch v := value.(type) {
		case map[string]any:
			tomlIntegerOptions(v)
		case float64:
			if v >= 0 && v <= 1<<53 && v == float64(int64(v)) {
				m[key] = int64(v)
			}
		}
	}
}
