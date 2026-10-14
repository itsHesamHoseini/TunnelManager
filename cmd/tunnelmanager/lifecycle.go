package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/itsHesamHoseini/TunnelManager/internal/config"
	"github.com/itsHesamHoseini/TunnelManager/internal/install"
	"github.com/itsHesamHoseini/TunnelManager/internal/secure"
	"golang.org/x/term"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

var input = bufio.NewReader(os.Stdin)

func ask(label, def string) (string, error) {
	fmt.Printf("%s [%s]: ", label, def)
	s, e := input.ReadString('\n')
	if e != nil && s == "" {
		return "", e
	}
	s = strings.TrimSpace(s)
	if s == "" {
		s = def
	}
	return s, nil
}
func secret(label string) (string, error) {
	fmt.Print(label + ": ")
	if term.IsTerminal(int(os.Stdin.Fd())) {
		b, e := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		return string(b), e
	}
	s, e := input.ReadString('\n')
	if e != nil && s == "" {
		return "", e
	}
	return strings.TrimSpace(s), nil
}
func lifecycle(args []string) error {
	command := args[0]
	var e error
	f := flag.NewFlagSet(command, flag.ContinueOnError)
	c := config.Default()
	if exe, err := os.Executable(); err == nil {
		if installed, err := config.Load(filepath.Join(filepath.Dir(exe), "installation.json")); err == nil {
			c = installed
		}
	}
	for i, a := range args {
		if a == "--config" && i+1 < len(args) {
			loaded, e := config.Load(args[i+1])
			if e != nil {
				return errors.New("config unavailable")
			}
			c = loaded
		}
	}
	f.Usage = func() {
		fmt.Fprintf(f.Output(), "TunnelManager %s\nExample: tunnelmanager %s --dir /opt/tunnelmanager\n", command, command)
		f.PrintDefaults()
	}
	yes := f.Bool("yes", false, "Confirm the displayed plan non-interactively")
	f.StringVar(&c.Mode, "mode", c.Mode, "controller or node")
	f.StringVar(&c.Dir, "dir", c.Dir, "Owned installation directory")
	f.StringVar(&c.ConfigDir, "config-dir", c.ConfigDir, "Protected runtime config directory")
	f.StringVar(&c.DataDir, "data-dir", c.DataDir, "Owned data directory (default /var/lib/tunnelmanager)")
	f.StringVar(&c.Domain, "domain", c.Domain, "Panel domain/IP")
	f.IntVar(&c.Port, "port", c.Port, "Panel port")
	f.StringVar(&c.TLS, "tls", c.TLS, "existing, self-signed, acme-http, acme-dns or proxy")
	f.StringVar(&c.Cert, "cert", c.Cert, "Existing PEM certificate")
	f.StringVar(&c.Key, "key", c.Key, "Existing PEM private key path")
	f.StringVar(&c.Language, "language", c.Language, "en or fa")
	f.StringVar(&c.Admin, "admin", c.Admin, "Initial administrator username")
	f.StringVar(&c.Bind, "bind", c.Bind, "Panel bind address")
	f.StringVar(&c.PublicURL, "public-url", c.PublicURL, "HTTPS origin when behind your own reverse proxy")
	f.StringVar(&c.Profile, "profile", c.Profile, "standard or strict")
	f.StringVar(&c.Controller, "controller", c.Controller, "Node controller HTTPS URL")
	f.StringVar(&c.CA, "ca", c.CA, "Explicit trusted controller CA file for private/self-signed TLS")
	cfgPath := f.String("config", "", "JSON configuration (valid YAML JSON subset)")
	passwordStdin := f.Bool("password-stdin", false, "Read initial admin password from protected stdin")
	tokenStdin := f.Bool("token-stdin", false, "Read one-time node token from protected input")
	saveCredentials := f.Bool("save-credentials", false, "Save generated credentials once in a root-only file")
	localNode := f.Bool("with-local-node", false, "Install and approve the controller host's own outbound agent")
	installDocker := f.Bool("install-docker", false, "Explicitly install Docker from official signed apt packages if absent")
	out := f.String("output", "", "Backup destination or redacted doctor JSON")
	backup := f.String("backup", "", "Encrypted backup to restore")
	replace := f.Bool("replace", false, "Explicitly replace controller database during restore")
	keep := f.Bool("keep-data", true, "Keep owned database and backups when uninstalling")
	binary := f.String("binary", "", "Verified local CLI binary for update")
	checksum := f.String("checksum", "", "Expected SHA256 for local update binary")
	resetMFA := f.Bool("reset-mfa", false, "Explicitly remove MFA enrollment along with password reset")
	parse := args[1:]
	if command == "config" && len(parse) > 0 && parse[0] == "show" {
		parse = parse[1:]
	}
	if e := f.Parse(parse); e != nil {
		if e == flag.ErrHelp {
			return nil
		}
		return e
	}
	_ = cfgPath
	_ = tokenStdin
	ctx, done := context.WithTimeout(context.Background(), 12*time.Minute)
	defer done()
	i := install.New()
	if command == "setup" {
		if runtime.GOOS != "linux" {
			return errors.New("setup requires Linux; use help for deployment options")
		}
		if !*yes {
			v, e := ask("Step 1 of 7 — Language (English is safest in terminals)", c.Language)
			if e != nil {
				return e
			}
			c.Language = v
			v, e = ask("Mode (controller/node)", c.Mode)
			if e != nil {
				return e
			}
			c.Mode = v
		}
		if c.Mode == "node" {
			return setupNode(ctx, c, *yes)
		}
		if _, e := exec.LookPath("docker"); e != nil {
			allow := *installDocker
			if !*yes && !allow {
				v, _ := ask("Docker absent. Install official signed apt packages? (yes/no)", "no")
				allow = v == "yes"
			}
			if allow {
				if e = i.InstallDocker(ctx); e != nil {
					return e
				}
			}
		}
		for _, x := range install.Preflight(c) {
			fmt.Println(x)
		}
		if !*yes {
			v, e := ask("Step 3 of 7 — Panel domain/IP", c.Domain)
			if e != nil {
				return e
			}
			c.Domain = v
			if addrs, e := net.LookupHost(c.Domain); e != nil || len(addrs) == 0 {
				fmt.Println("DNS not resolved. Verify DNS before external access.")
			}
			v, e = ask("Panel port", fmt.Sprint(c.Port))
			if e != nil {
				return e
			}
			fmt.Sscan(v, &c.Port)
			v, e = ask("Installation directory", c.Dir)
			if e != nil {
				return e
			}
			c.Dir = v
			v, e = ask("Step 4 of 7 — TLS (existing/self-signed/acme-http/acme-dns/proxy)", c.TLS)
			if e != nil {
				return e
			}
			c.TLS = v
			if c.TLS == "existing" {
				c.Cert, _ = ask("Certificate PEM file", c.Cert)
				c.Key, _ = ask("Private key PEM file", c.Key)
			}
			v, e = ask("Step 5 of 7 — Administrator username", c.Admin)
			if e != nil {
				return e
			}
			c.Admin = v
			fmt.Println("TOTP enrollment with QR and recovery codes is required at first login.")
		}
		if e = install.Validate(c); e != nil {
			return e
		}
		_, existingErr := os.Stat(filepath.Join(c.Dir, "installation.json"))
		existing := existingErr == nil
		password := ""
		if !existing {
			if *passwordStdin {
				password, e = secret("Admin password")
				if e != nil {
					return e
				}
			} else if !*yes {
				password, e = secret("Password (blank generates a strong one)")
				if e != nil {
					return e
				}
			}
			if password == "" {
				if *yes && !*saveCredentials {
					return errors.New("use --password-stdin or --save-credentials; secrets will not be printed in automated mode")
				}
				password = secure.Token(24)
				if !*saveCredentials {
					fmt.Println("Generated password (shown once):", password)
				}
			}
			if len(password) < 16 {
				return errors.New("use a password of at least 16 characters")
			}
		}
		if !*yes {
			fmt.Println("Step 6 of 7 — Telegram is optional and can be configured/tested in the authenticated web settings.")
			v, _ := ask("Rate-limit profile", c.Profile)
			c.Profile = v
			fmt.Printf("Step 7 of 7 — Plan: controller %s; directory %s; config %s; TLS %s. No SSH, tunnel or firewall edits.\n", c.Origin(), c.Dir, c.ConfigDir, c.TLS)
			if c.TLS == "acme-http" || c.TLS == "acme-dns" {
				fmt.Println("This requests a Let's Encrypt certificate and accepts its subscriber terms.")
			}
			v, e := ask("Install/repair this plan? (yes/no)", "no")
			if e != nil {
				return e
			}
			if v != "yes" {
				return errors.New("cancelled; nothing installed")
			}
		}
		if e = i.Setup(ctx, c, password, *saveCredentials); e != nil {
			return e
		}
		if !*yes && !existing {
			if e = terminalOnboarding(ctx, c, password); e != nil {
				fmt.Println("Controller installed; finish protected onboarding in the web panel.")
				return e
			}
		}
		if *localNode {
			if e = firstNode(ctx, c); e != nil {
				return e
			}
		}
		if *saveCredentials && !existing {
			fmt.Println("Login details saved root-only under the runtime config directory, credentials.once.")
		}
		return linkCLI(c)
	}
	if c.Mode == "node" {
		if c.Dir == "/opt/tunnelmanager" {
			c.Dir = "/opt/tunnelmanager-agent"
		}
		if c.ConfigDir == "/etc/tunnelmanager" {
			c.ConfigDir = "/etc/tunnelmanager-agent"
		}
	}
	installed, e := config.Load(filepath.Join(c.Dir, "installation.json"))
	if e == nil {
		c = installed
	} else if command != "doctor" && command != "config" {
		return errors.New("installation marker unavailable; use setup or specify --dir")
	}
	if command == "config" {
		b, _ := json.MarshalIndent(c, "", "  ")
		fmt.Println(string(b))
		fmt.Println("Private key, database password and account secrets are masked (not read).")
		return nil
	}
	if command == "doctor" {
		checks := install.Preflight(c)
		report := map[string]any{"version": version, "mode": c.Mode, "os": runtime.GOOS, "architecture": runtime.GOARCH, "checks": checks, "config_present": e == nil}
		if c.Mode == "controller" {
			b, err := i.Compose(ctx, c, []string{"ps", "--format", "json"}, nil)
			if err == nil {
				report["containers"] = string(b)
			}
			_, err = i.Compose(ctx, c, []string{"exec", "-T", "controller", "/tunnelmanager", "healthcheck"}, nil)
			report["controller_healthy"] = err == nil
		} else {
			b, err := install.Run(ctx, "systemctl", []string{"is-active", "tunnelmanager-agent.service"}, nil)
			report["agent_active"] = err == nil && strings.TrimSpace(string(b)) == "active"
			if state, err := os.ReadFile("/var/lib/tunnelmanager-agent/status.json"); err == nil {
				var v map[string]any
				if json.Unmarshal(state, &v) == nil {
					report["connection"] = v
				}
			}
			report["health_scope"] = "process and agent connection only; not tunnel health"
		}
		b, _ := json.MarshalIndent(report, "", "  ")
		if *out != "" {
			return config.Atomic(*out, b, 0600)
		}
		fmt.Println(string(b))
		return nil
	}
	if command == "status" {
		if c.Mode == "node" {
			b, e := install.Run(ctx, "systemctl", []string{"show", "tunnelmanager-agent.service", "--property=ActiveState,SubState,MainPID"}, nil)
			if e != nil {
				return e
			}
			fmt.Print(string(b))
			return nil
		}
		b, e := i.Compose(ctx, c, []string{"ps"}, nil)
		if e != nil {
			return e
		}
		fmt.Print(string(b))
		fmt.Println("Panel:", c.Origin())
		return nil
	}
	if command == "logs" {
		if c.Mode == "node" {
			b, e := install.Run(ctx, "journalctl", []string{"-u", "tunnelmanager-agent.service", "--no-pager", "-n", "100", "-o", "cat"}, nil)
			if e != nil {
				return e
			}
			fmt.Print(string(b))
			return nil
		}
		b, e := i.Compose(ctx, c, []string{"logs", "--tail", "100", "controller"}, nil)
		if e != nil {
			return e
		}
		fmt.Print(string(b))
		return nil
	}
	if command == "backup" {
		if *out == "" {
			return errors.New("--output is required")
		}
		pass, e := secret("Independent backup passphrase (16+ characters)")
		if e != nil {
			return e
		}
		if e = i.Backup(ctx, c, *out, pass); e != nil {
			return e
		}
		fmt.Println("Encrypted backup saved; keep its passphrase separate.")
		return nil
	}
	if command == "restore" {
		if *backup == "" {
			return errors.New("--backup is required")
		}
		fmt.Println("Restore replaces controller state, revokes sessions, preserves host tunnel services.")
		if !*yes {
			v, e := ask("Replace controller state? (yes/no)", "no")
			if e != nil {
				return e
			}
			if v != "yes" {
				return errors.New("cancelled")
			}
			*replace = true
		}
		pass, e := secret("Backup passphrase")
		if e != nil {
			return e
		}
		return i.Restore(ctx, c, *backup, pass, *replace)
	}
	if command == "reset-admin-password" {
		if !*yes {
			v, _ := ask("Reset password and revoke all sessions? (yes/no)", "no")
			if v != "yes" {
				return errors.New("cancelled")
			}
		}
		pass, e := secret("New admin password (16+ characters)")
		if e != nil || len(pass) < 16 {
			return errors.New("password must be at least 16 characters")
		}
		payload, _ := json.Marshal(map[string]any{"Password": pass, "ResetMFA": *resetMFA})
		_, e = i.Compose(ctx, c, []string{"exec", "-T", "controller", "/tunnelmanager", "reset-admin-internal", "--config", "/config/controller.json"}, bytes.NewReader(payload))
		return e
	}
	if command == "update" {
		if *binary == "" || len(*checksum) != 64 {
			return errors.New("provide --binary and its trusted --checksum")
		}
		b, e := os.ReadFile(*binary)
		if e != nil {
			return e
		}
		sum := sha256.Sum256(b)
		if fmt.Sprintf("%x", sum) != strings.ToLower(*checksum) {
			return errors.New("binary checksum mismatch; nothing changed")
		}
		fmt.Println("Update snapshots files and database; failed health restores the previous version.")
		if !*yes {
			v, _ := ask("Apply update? (yes/no)", "no")
			if v != "yes" {
				return errors.New("cancelled")
			}
		}
		staged := filepath.Join(c.Dir, ".runtime", "update-binary")
		if e = config.Atomic(staged, b, 0755); e != nil {
			return e
		}
		_, e = install.Run(ctx, staged, []string{"setup", "--yes", "--config", filepath.Join(c.Dir, "installation.json")}, nil)
		return e
	}
	if command == "uninstall" {
		fmt.Println("Remove only owned controller containers / native agent unit. Data kept by default.")
		if !*yes {
			v, _ := ask("Uninstall? (yes/no)", "no")
			if v != "yes" {
				return errors.New("cancelled")
			}
		}
		if c.Mode == "node" {
			return uninstallNode(ctx, c, *keep)
		}
		args := []string{"down"}
		if !*keep {
			args = append(args, "--volumes")
		}
		_, e = i.Compose(ctx, c, args, nil)
		return e
	}
	return fmt.Errorf("unknown command %q; use --help", command)
}
func linkCLI(c config.Config) error {
	path := "/usr/local/bin/tunnelmanager"
	target := filepath.Join(c.Dir, "tunnelmanager")
	if old, e := os.Readlink(path); e == nil {
		if old != target {
			return errors.New("CLI link belongs to another installation; retained")
		}
		return nil
	}
	if _, e := os.Lstat(path); e == nil {
		return nil
	}
	return os.Symlink(target, path)
}
func readStdinLimited() (string, error) {
	b, e := io.ReadAll(io.LimitReader(os.Stdin, 65536))
	return strings.TrimSpace(string(b)), e
}
