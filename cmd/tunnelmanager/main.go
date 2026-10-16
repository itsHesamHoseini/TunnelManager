package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/itsHesamHoseini/TunnelManager/internal/agent"
	"github.com/itsHesamHoseini/TunnelManager/internal/config"
	"github.com/itsHesamHoseini/TunnelManager/internal/controller"
	"github.com/itsHesamHoseini/TunnelManager/internal/nodeops"
	"github.com/itsHesamHoseini/TunnelManager/internal/secure"
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
	case "local-rollback":
		f := flag.NewFlagSet("local-rollback", flag.ContinueOnError)
		id := f.String("id", "", "Owned change ID")
		dir := f.String("config-dir", "/etc/tunnelmanager-agent", "Node config directory")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		ops := nodeops.New(config.Config{ConfigDir: *dir})
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		return ops.Rollback(ctx, *id)
	case "edge":
		return edge(args[1:])
	case "agent":
		f := flag.NewFlagSet("agent", flag.ContinueOnError)
		p := f.String("config", "/etc/tunnelmanager-agent/node.json", "Native agent config")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		c, e := config.Load(*p)
		if e != nil {
			return fmt.Errorf("node configuration unavailable")
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return agent.Run(ctx, c)
	case "version":
		fmt.Println("TunnelManager", version)
		return nil
	case "help", "--help", "-h":
		help()
		return nil
	case "healthcheck":
		f := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
		u := f.String("url", "http://127.0.0.1:8080/healthz", "Health endpoint")
		ca := f.String("ca", "", "Explicit CA file")
		serverName := f.String("server-name", "", "TLS server name for local health checks")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		c := http.Client{Timeout: 2 * time.Second}
		if *ca != "" {
			b, e := os.ReadFile(*ca)
			if e != nil {
				return fmt.Errorf("health trust unavailable")
			}
			pool, _ := x509.SystemCertPool()
			if pool == nil {
				pool = x509.NewCertPool()
			}
			if !pool.AppendCertsFromPEM(b) {
				return fmt.Errorf("invalid health CA")
			}
			c.Transport = &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: *serverName}}
		}
		r, e := c.Get(*u)
		if e != nil {
			return fmt.Errorf("health endpoint unavailable")
		}
		r.Body.Close()
		if r.StatusCode != 200 {
			return fmt.Errorf("controller not ready")
		}
		return nil
	case "serve", "bootstrap-admin", "reset-admin-internal", "enrollment-internal":
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
		s, e := controller.New(ctx, controller.Config{Address: ":8080", Origin: cfg.Origin(), DatabaseURL: db, Key: key, TrustProxy: true, Static: ui.Handler(), Profile: cfg.Profile, Language: cfg.Language, PolicyDirectory: "/policy"})
		if e != nil {
			return fmt.Errorf("controller startup failed (check database and key)")
		}
		defer s.Close()
		if args[0] == "reset-admin-internal" {
			var q struct {
				Password string
				ResetMFA bool
			}
			if e = json.NewDecoder(os.Stdin).Decode(&q); e != nil || len(q.Password) < 16 {
				return fmt.Errorf("password input invalid")
			}
			tx, e := s.DB.Begin(ctx)
			if e != nil {
				return e
			}
			defer tx.Rollback(ctx)
			if _, e = tx.Exec(ctx, "UPDATE admins SET password_hash=$1 WHERE id=1", secure.Password(q.Password)); e != nil {
				return e
			}
			if q.ResetMFA {
				tx.Exec(ctx, "UPDATE admins SET totp=NULL,totp_step=-1 WHERE id=1")
				tx.Exec(ctx, "DELETE FROM recovery")
			}
			if _, e = tx.Exec(ctx, "DELETE FROM sessions; DELETE FROM challenges;"); e != nil {
				return e
			}
			if e = tx.Commit(ctx); e != nil {
				return e
			}
			s.Audit(ctx, "admin-password-reset", "", "success")
			return nil
		}
		if args[0] == "enrollment-internal" {
			var q struct {
				Name, Role  string
				AutoApprove bool
			}
			if e = json.NewDecoder(os.Stdin).Decode(&q); e != nil {
				return fmt.Errorf("enrollment input invalid")
			}
			token, e := s.CreateEnrollment(ctx, q.Name, q.Role, q.AutoApprove)
			if e != nil {
				return e
			}
			return json.NewEncoder(os.Stdout).Encode(map[string]string{"token": token})
		}
		if args[0] == "bootstrap-admin" {
			var q struct{ Username, Password string }
			if e = json.NewDecoder(os.Stdin).Decode(&q); e != nil {
				return fmt.Errorf("admin input invalid")
			}
			return s.InitAdmin(ctx, q.Username, q.Password)
		}
		go s.TelegramLoop(ctx)
		go s.Maintenance(ctx)
		go s.Operations(ctx)
		go s.Monitor(ctx)
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
		return lifecycle(args)
	}
}
func help() {
	fmt.Println("TunnelManager 0.3.0\nCommands: setup, status, doctor, update, uninstall, backup, restore, reset-admin-password, config show, logs, version.\nExample: tunnelmanager setup --mode controller --domain panel.example.com --port 9443\nUse tunnelmanager COMMAND --help for details.")
}
