package nodeops

import (
	"testing"
	"time"
)

func TestRecoveryRequiresSustainedObservationsAndRespectsLimits(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	p := RecoveryPolicy{SustainedSeconds: 60, CooldownSeconds: 120, DailyLimit: 2}
	if p.Ready(now, true) || p.Ready(now.Add(30*time.Second), true) || !p.Ready(now.Add(time.Minute), true) {
		t.Fatal("sustained duration ignored")
	}
	last := now.Add(time.Minute)
	p.Last = &last
	p.Count = 1
	if p.Ready(now.Add(90*time.Second), true) {
		t.Fatal("cooldown ignored")
	}
	if p.Ready(now.Add(4*time.Minute), true) {
		t.Fatal("missing observation gap counted as sustained")
	}
	p.Ready(now.Add(4*time.Minute+30*time.Second), true)
	if !p.Ready(now.Add(5*time.Minute), true) {
		t.Fatal("fresh sustained observation not recognized")
	}
	p.Count = 2
	if p.Ready(now.Add(5*time.Minute+30*time.Second), true) {
		t.Fatal("daily ceiling ignored")
	}
	p.Ready(now.Add(6*time.Minute), false)
	if p.Since != nil {
		t.Fatal("recovered usage did not reset duration")
	}
	p.Ready(now.Add(24*time.Hour), true)
	if p.Count != 0 {
		t.Fatal("UTC daily counter did not advance")
	}
}
