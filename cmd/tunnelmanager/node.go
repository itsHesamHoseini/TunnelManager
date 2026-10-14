package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/itsHesamHoseini/TunnelManager/internal/agent"
	"github.com/itsHesamHoseini/TunnelManager/internal/config"
	"github.com/itsHesamHoseini/TunnelManager/internal/install"
	"github.com/itsHesamHoseini/TunnelManager/internal/secure"
	"os"
	"path/filepath"
	"strings"
)

func setupNode(ctx context.Context, c config.Config, yes bool) error {
	if c.Dir == "/opt/tunnelmanager" {
		c.Dir = "/opt/tunnelmanager-agent"
	}
	if c.ConfigDir == "/etc/tunnelmanager" {
		c.ConfigDir = "/etc/tunnelmanager-agent"
	}
	if os.Geteuid() != 0 {
		return errors.New("native node setup requires sudo/root")
	}
	if c.Controller == "" {
		v, e := ask("Controller HTTPS origin", "")
		if e != nil {
			return e
		}
		c.Controller = v
	}
	if old, e := config.Load(filepath.Join(c.ConfigDir, "node.json")); e == nil && old.NodeID != "" {
		c = old
		fmt.Println("Existing node identity retained; repairing owned agent unit.")
	} else {
		if !yes {
			v, e := ask("Install native agent, outbound only; no SSH changes? (yes/no)", "no")
			if e != nil {
				return e
			}
			if v != "yes" {
				return errors.New("cancelled")
			}
		}
		token, e := secret("One-time enrollment token")
		if e != nil {
			return e
		}
		c, e = agent.Enroll(ctx, c, token)
		if e != nil {
			return e
		}
	}
	if e := os.MkdirAll(c.Dir, 0700); e != nil {
		return e
	}
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	if e = install.CopyFile(exe, filepath.Join(c.Dir, "tunnelmanager"), 0755); e != nil {
		return e
	}
	unit := "[Unit]\nDescription=TunnelManager outbound node agent\nAfter=network-online.target\nWants=network-online.target\n[Service]\nType=simple\nExecStart=" + filepath.Join(c.Dir, "tunnelmanager") + " agent --config " + filepath.Join(c.ConfigDir, "node.json") + "\nRestart=on-failure\nRestartSec=10\nUMask=0077\nNoNewPrivileges=true\nProtectSystem=strict\nProtectHome=true\nPrivateTmp=true\nProtectKernelTunables=true\nProtectControlGroups=true\nMemoryMax=96M\nCPUQuota=15%\nTasksMax=32\nStateDirectory=tunnelmanager-agent\nStateDirectoryMode=0700\nReadWritePaths=/var/lib/tunnelmanager-agent\n[Install]\nWantedBy=multi-user.target\n"
	if strings.ContainsAny(c.Dir+c.ConfigDir, " \t\n\r\"") {
		return errors.New("native unit paths must not contain whitespace or quotes")
	}
	if e = config.Atomic("/etc/systemd/system/tunnelmanager-agent.service", []byte(unit), 0644); e != nil {
		return e
	}
	if _, e = install.Run(ctx, "systemctl", []string{"daemon-reload"}, nil); e != nil {
		return e
	}
	if _, e = install.Run(ctx, "systemctl", []string{"enable", "--now", "tunnelmanager-agent.service"}, nil); e != nil {
		return e
	}
	if e = config.Write(filepath.Join(c.Dir, "installation.json"), c); e != nil {
		return e
	}
	fmt.Println("Node installed. Waiting for explicit identity approval in the panel.")
	if key, e := os.ReadFile(c.Identity); e == nil && len(key) == 64 {
		fmt.Println("Node public identity:", secure.Fingerprint(ed25519.PrivateKey(key).Public().(ed25519.PublicKey)))
	}
	return nil
}
func uninstallNode(ctx context.Context, c config.Config, keep bool) error {
	if _, e := install.Run(ctx, "systemctl", []string{"disable", "--now", "tunnelmanager-agent.service"}, nil); e != nil {
		return e
	}
	if e := os.Remove("/etc/systemd/system/tunnelmanager-agent.service"); e != nil && !os.IsNotExist(e) {
		return e
	}
	_, e := install.Run(ctx, "systemctl", []string{"daemon-reload"}, nil)
	if e != nil {
		return e
	}
	if target, err := os.Readlink("/usr/local/bin/tunnelmanager"); err == nil && target == filepath.Join(c.Dir, "tunnelmanager") {
		os.Remove("/usr/local/bin/tunnelmanager")
	}
	if !keep {
		if c.ConfigDir != "/etc/tunnelmanager-agent" {
			return errors.New("non-default node data preserved; inspect manually")
		}
		return os.Remove(filepath.Join(c.ConfigDir, "identity.key"))
	}
	return nil
}
func firstNode(ctx context.Context, c config.Config) error {
	if old, e := config.Load("/etc/tunnelmanager-agent/node.json"); e == nil && old.NodeID != "" {
		if old.Controller != c.Origin() {
			return errors.New("existing local agent belongs to a different controller origin; retained")
		}
		return setupNode(ctx, old, true)
	}
	i := install.New()
	payload, _ := json.Marshal(map[string]any{"Name": "Controller host", "Role": "foreign", "AutoApprove": true})
	b, e := i.Compose(ctx, c, []string{"exec", "-T", "controller", "/tunnelmanager", "enrollment-internal", "--config", "/config/controller.json"}, bytes.NewReader(payload))
	if e != nil {
		return e
	}
	var v struct {
		Token string `json:"token"`
	}
	if json.Unmarshal(b, &v) != nil || v.Token == "" {
		return errors.New("local enrollment unavailable")
	}
	node := config.Default()
	node.Mode = "node"
	node.Dir = "/opt/tunnelmanager-agent"
	node.ConfigDir = "/etc/tunnelmanager-agent"
	node.Controller = c.Origin()
	if c.TLS == "self-signed" {
		node.CA = filepath.Join(node.ConfigDir, "controller-ca.pem")
		if e = install.CopyFile(filepath.Join(c.ConfigDir, "tls/cert.pem"), node.CA, 0600); e != nil {
			return e
		}
	}
	node, e = agent.Enroll(ctx, node, v.Token)
	if e != nil {
		return e
	}
	return setupNode(ctx, node, true)
}
