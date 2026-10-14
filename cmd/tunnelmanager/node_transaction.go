package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/itsHesamHoseini/TunnelManager/internal/config"
	"github.com/itsHesamHoseini/TunnelManager/internal/install"
)

func nodeRollback(c config.Config, existed bool) (func() error, error) {
	snapshot, e := install.Snapshot(c)
	if e != nil {
		return nil, e
	}
	unitPath := "/etc/systemd/system/tunnelmanager-agent.service"
	if existed {
		if e = install.CopyFile(unitPath, filepath.Join(snapshot, "node.service"), 0600); e != nil {
			return nil, e
		}
	}
	ctx, done := context.WithTimeout(context.Background(), 10*time.Second)
	defer done()
	active, e := install.Run(ctx, "systemctl", []string{"is-active", "tunnelmanager-agent.service"}, nil)
	wasActive := e == nil && strings.TrimSpace(string(active)) == "active"
	enabled, e := install.Run(ctx, "systemctl", []string{"is-enabled", "tunnelmanager-agent.service"}, nil)
	wasEnabled := e == nil && strings.TrimSpace(string(enabled)) == "enabled"
	state := "inactive"
	if wasActive {
		state = "active"
	}
	if wasEnabled {
		state += " enabled"
	}
	if e = config.Atomic(filepath.Join(snapshot, "node-state"), []byte(state), 0600); e != nil {
		return nil, e
	}
	return func() error {
		ctx, done := context.WithTimeout(context.Background(), time.Minute)
		defer done()
		install.Run(ctx, "systemctl", []string{"stop", "tunnelmanager-agent.service"}, nil)
		if !existed {
			install.Run(ctx, "systemctl", []string{"disable", "tunnelmanager-agent.service"}, nil)
			if e := os.Remove(unitPath); e != nil && !os.IsNotExist(e) {
				return e
			}
			_, e := install.Run(ctx, "systemctl", []string{"daemon-reload"}, nil)
			return e
		}
		if e := install.RestoreSnapshot(c, snapshot); e != nil {
			return e
		}
		if e := install.CopyFile(filepath.Join(snapshot, "node.service"), unitPath, 0644); e != nil {
			return e
		}
		if _, e := install.Run(ctx, "systemctl", []string{"daemon-reload"}, nil); e != nil {
			return e
		}
		enable := "disable"
		if wasEnabled {
			enable = "enable"
		}
		if _, e := install.Run(ctx, "systemctl", []string{enable, "tunnelmanager-agent.service"}, nil); e != nil {
			return e
		}
		if wasActive {
			if _, e := install.Run(ctx, "systemctl", []string{"start", "tunnelmanager-agent.service"}, nil); e != nil {
				return errors.New("previous agent failed to restart; protected snapshot retained")
			}
		}
		return nil
	}, nil
}
