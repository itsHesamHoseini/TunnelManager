package controller

import (
	"encoding/json"
	"time"
)

// Only authenticated connection and an actual recent observation establish
// current node availability. This does not assert any tunnel/application health.
func observationState(approved, connected bool, seen *time.Time, raw []byte, now time.Time) (bool, bool, string) {
	var sample map[string]json.RawMessage
	hasSample := json.Unmarshal(raw, &sample) == nil && len(sample) > 0
	fresh := hasSample && seen != nil && !seen.After(now) && now.Sub(*seen) <= 90*time.Second
	if !approved {
		return false, fresh, "approval_pending"
	}
	if !hasSample || seen == nil {
		return false, false, "no_observations"
	}
	if !connected {
		return false, fresh, "agent_disconnected"
	}
	if !fresh {
		return false, false, "observation_stale"
	}
	return true, true, "fresh_observation"
}
