package engine

// Option describes the existing bounded adapter, not every upstream capability.
// Upstream defaults: Musixal/Backhaul v0.7.2 cmd/defaults.go and config/config.go.
// skip_optz is deliberately true in our renderer to preserve OS settings.
type Option struct {
	Key     string   `json:"key"`
	Kind    string   `json:"kind"`
	Default any      `json:"default"`
	Max     int      `json:"max,omitempty"`
	Roles   []string `json:"roles"`
	Choices []string `json:"choices,omitempty"`
}

var SupportedOptions = []Option{
	{"connection_pool", "number", 8, 256, []string{"client"}, nil},
	{"retry_interval", "number", 3, 300, []string{"client"}, nil},
	{"dial_timeout", "number", 10, 60, []string{"client"}, nil},
	{"aggressive_pool", "boolean", false, 0, []string{"client"}, nil},
	{"heartbeat", "number", 40, 300, []string{"server"}, nil},
	{"channel_size", "number", 2048, 4096, []string{"server"}, nil},
	{"mux_con", "number", 8, 64, []string{"server"}, nil},
	{"keepalive_period", "number", 75, 300, []string{"server", "client"}, nil},
	{"nodelay", "boolean", false, 0, []string{"server", "client"}, nil},
	{"mux_version", "number", 1, 2, []string{"server", "client"}, nil},
	{"mux_framesize", "number", 32768, 65535, []string{"server", "client"}, nil},
	{"mux_recievebuffer", "number", 4194304, 16777216, []string{"server", "client"}, nil},
	{"mux_streambuffer", "number", 65536, 16777216, []string{"server", "client"}, nil},
	{"skip_optz", "boolean", true, 0, []string{"server", "client"}, nil},
	{"log_level", "choice", "info", 0, []string{"server", "client"}, []string{"trace", "debug", "info", "warn", "error", "fatal", "panic"}},
}
