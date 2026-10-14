package controller

import (
	"github.com/itsHesamHoseini/TunnelManager/internal/config"
)

func runtimeConfigAtomic(path string, b []byte) error { return config.Atomic(path, b, 0600) }
