//go:build !linux

package agent

import (
	"context"
	"github.com/itsHesamHoseini/TunnelManager/internal/protocol"
	"time"
)

type Sampler struct{}

func NewSampler() *Sampler { return &Sampler{} }
func (s *Sampler) Collect(ctx context.Context) protocol.Telemetry {
	return protocol.Telemetry{At: time.Now(), Errors: []string{"Native metrics require Linux; measurements untested on this OS."}, Scope: "unsupported OS; no host measurements"}
}
