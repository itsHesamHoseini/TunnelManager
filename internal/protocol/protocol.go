package protocol

import (
	"time"
)

const Version = 1
const MaxFrame = 256 * 1024

type Hello struct {
	Nonce   string    `json:"nonce"`
	Expires time.Time `json:"expires"`
}
type Authentication struct {
	NodeID    string `json:"node_id"`
	Signature string `json:"signature"`
}
type Frame struct {
	Type    string     `json:"type"`
	Version int        `json:"version"`
	Data    *Telemetry `json:"data,omitempty"`
}
type Process struct {
	PID    int      `json:"pid"`
	Name   string   `json:"name"`
	CPU    *float64 `json:"cpu_percent"`
	RAM    uint64   `json:"ram_bytes"`
	Uptime float64  `json:"uptime_seconds"`
	Engine bool     `json:"engine"`
}
type Listener struct {
	Address  string `json:"address"`
	Protocol string `json:"protocol"`
	Process  string `json:"process"`
	PID      int    `json:"pid"`
}
type Service struct {
	Name    string `json:"name"`
	Active  string `json:"active"`
	Enabled string `json:"enabled"`
}
type Network struct {
	Name   string   `json:"name"`
	RX     uint64   `json:"rx_bytes"`
	TX     uint64   `json:"tx_bytes"`
	RXRate *float64 `json:"rx_bytes_per_second"`
	TXRate *float64 `json:"tx_bytes_per_second"`
}
type Telemetry struct {
	At        time.Time  `json:"at"`
	OS        string     `json:"os"`
	CPU       *float64   `json:"cpu_percent"`
	RAMTotal  uint64     `json:"ram_total"`
	RAMUsed   uint64     `json:"ram_used"`
	DiskTotal uint64     `json:"disk_total"`
	DiskFree  uint64     `json:"disk_free"`
	Networks  []Network  `json:"networks"`
	Processes []Process  `json:"processes"`
	Listeners []Listener `json:"listeners"`
	Services  []Service  `json:"services"`
	Errors    []string   `json:"errors"`
	Scope     string     `json:"scope"`
}
