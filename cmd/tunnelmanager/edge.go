package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/itsHesamHoseini/TunnelManager/internal/config"
	"github.com/itsHesamHoseini/TunnelManager/internal/deploy"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func edge(args []string) error {
	f := flag.NewFlagSet("edge", flag.ContinueOnError)
	plain := f.Bool("plain", false, "HTTP behind an explicitly configured HTTPS reverse proxy")
	if e := f.Parse(args); e != nil {
		return e
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	template, e := deploy.Templates.ReadFile("templates/nginx.conf")
	if e != nil {
		return e
	}
	base := string(template)
	if *plain {
		base = strings.Replace(base, "listen 9443 ssl;", "listen 9443;", 1)
		for _, line := range []string{"ssl_certificate /tls/cert.pem;", "ssl_certificate_key /tls/key.pem;", "ssl_protocols TLSv1.2 TLSv1.3;"} {
			base = strings.Replace(base, line, "", 1)
		}
	}
	current := ""
	started := false
	var cmd *exec.Cmd
	var exited chan error
	apply := func(profile string) error {
		if profile != "strict" {
			profile = "standard"
		}
		str := base
		if profile == "strict" {
			str = strings.Replace(str, "rate=10r/s;", "rate=5r/s;", 1)
			str = strings.Replace(str, "rate=10r/m;", "rate=5r/m;", 1)
			str = strings.Replace(str, "limit_conn connections 20;", "limit_conn connections 10;", 1)
		}
		candidate := "/tmp/tunnelmanager-nginx-next.conf"
		if e = config.Atomic(candidate, []byte(str), 0600); e != nil {
			return e
		}
		test := exec.CommandContext(ctx, "nginx", "-t", "-c", candidate)
		if b, e := test.CombinedOutput(); e != nil {
			if strings.Contains(strings.ToLower(string(b)), "permission denied") {
				return errors.New("edge cannot read protected TLS files: keep them owned by the container's matching root identity; do not make private keys public")
			}
			if strings.Contains(strings.ToLower(string(b)), "host not found") {
				return errors.New("edge controller DNS is not ready")
			}
			return errors.New("edge configuration validation failed")
		}
		if e = config.Atomic("/tmp/tunnelmanager-nginx.conf", []byte(str), 0600); e != nil {
			return e
		}
		if started {
			reload := exec.CommandContext(ctx, "nginx", "-s", "reload", "-c", "/tmp/tunnelmanager-nginx.conf")
			if e = reload.Run(); e != nil {
				return errors.New("edge reload failed")
			}
		}
		current = profile
		state, _ := json.Marshal(map[string]any{"profile": profile, "at": time.Now().UTC(), "applied": true})
		return config.Atomic("/policy/observed.json", state, 0600)
	}
	read := func() string {
		b, e := os.ReadFile("/policy/desired.json")
		if e != nil {
			return "standard"
		}
		var p struct {
			Profile string `json:"profile"`
		}
		if json.Unmarshal(b, &p) != nil {
			return "standard"
		}
		if p.Profile == "strict" {
			return "strict"
		}
		return "standard"
	}
	if e = apply(read()); e != nil {
		return e
	}
	cmd = exec.Command("nginx", "-c", "/tmp/tunnelmanager-nginx.conf", "-g", "daemon off;")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if e = cmd.Start(); e != nil {
		return e
	}
	started = true
	exited = make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			cmd.Process.Signal(syscall.SIGTERM)
			select {
			case <-exited:
				return nil
			case <-time.After(5 * time.Second):
				cmd.Process.Kill()
				return nil
			}
		case e := <-exited:
			if e != nil {
				return fmt.Errorf("edge process stopped")
			}
			return nil
		case <-ticker.C:
			profile := read()
			if profile != current {
				if e = apply(profile); e != nil {
					state, _ := json.Marshal(map[string]any{"profile": current, "applied": false, "error": "reload_failed", "at": time.Now().UTC()})
					config.Atomic("/policy/observed.json", state, 0600)
				}
			}
		}
	}
}
