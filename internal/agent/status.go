package agent

import (
	"encoding/json"
	"github.com/itsHesamHoseini/TunnelManager/internal/config"
	"time"
)

func saveStatus(phase string, at time.Time) {
	b, _ := json.Marshal(map[string]any{"phase": phase, "last_ack": at, "written_at": time.Now().UTC(), "scope": "agent connection; not tunnel health"})
	config.Atomic("/var/lib/tunnelmanager-agent/status.json", b, 0600)
}
