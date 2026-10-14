package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/itsHesamHoseini/TunnelManager/internal/config"
	"github.com/itsHesamHoseini/TunnelManager/internal/controller"
	"github.com/itsHesamHoseini/TunnelManager/internal/ui"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

const version = "0.3.0"

func main() {
	if e := run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, "TunnelManager:", e)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 {
		help()
		return nil
	}
	switch args[0] {
	case "version":
		fmt.Println("TunnelManager", version)
		return nil
	case "help", "--help", "-h":
		help()
		return nil
	case "healthcheck":
		f := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
		u := f.String("url", "http://127.0.0.1:8080/healthz", "Health endpoint")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		c := http.Client{Timeout: 2 * time.Second}
		r, e := c.Get(*u)
		if e != nil {
			return fmt.Errorf("health endpoint unavailable")
		}
		r.Body.Close()
		if r.StatusCode != 200 {
			return fmt.Errorf("controller not ready")
		}
		return nil
	case "serve", "bootstrap-admin":
		f := flag.NewFlagSet(args[0], flag.ContinueOnError)
		p := f.String("config", "/etc/tunnelmanager/controller.json", "Runtime configuration path")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		cfg, e := config.Load(*p)
		if e != nil {
			return fmt.Errorf("runtime config unavailable")
		}
		key, e := os.ReadFile(filepath.Join(cfg.ConfigDir, "master.key"))
		if e != nil {
			return fmt.Errorf("master key unavailable")
		}
		db, e := cfg.DatabaseURL()
		if e != nil {
			return fmt.Errorf("database secret unavailable")
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		s, e := controller.New(ctx, controller.Config{Address: ":8080", Origin: cfg.Origin(), DatabaseURL: db, Key: key, TrustProxy: true, Static: ui.Handler(), Profile: cfg.Profile})
		if e != nil {
			return fmt.Errorf("controller startup failed (check database and key)")
		}
		defer s.Close()
		if args[0] == "bootstrap-admin" {
			var q struct{ Username, Password string }
			if e = json.NewDecoder(os.Stdin).Decode(&q); e != nil {
				return fmt.Errorf("admin input invalid")
			}
			return s.InitAdmin(ctx, q.Username, q.Password)
		}
		go s.TelegramLoop(ctx)
		go s.Maintenance(ctx)
		srv := http.Server{Addr: ":8080", Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024}
		go func() {
			<-ctx.Done()
			c, done := context.WithTimeout(context.Background(), 5*time.Second)
			defer done()
			srv.Shutdown(c)
		}()
		e = srv.ListenAndServe()
		if e == http.ErrServerClosed {
			return nil
		}
		return e
	default:
		return fmt.Errorf("command belongs to the installer milestone; not available yet")
	}
}
func help() {
	fmt.Println("TunnelManager 0.3.0\nCommands: setup, status, doctor, update, uninstall, backup, restore, reset-admin-password, config show, logs, version.\nExample: tunnelmanager setup --mode controller --domain panel.example.com --port 9443\nUse tunnelmanager COMMAND --help for details.")
}
