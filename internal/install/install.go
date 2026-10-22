package install

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/itsHesamHoseini/TunnelManager/internal/config"
	"github.com/itsHesamHoseini/TunnelManager/internal/deploy"
	"github.com/itsHesamHoseini/TunnelManager/internal/secure"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

type Runner func(context.Context, string, []string, io.Reader) ([]byte, error)

func Run(ctx context.Context, program string, args []string, input io.Reader) ([]byte, error) {
	cmd := exec.CommandContext(ctx, program, args...)
	cmd.Stdin = input
	b, e := cmd.CombinedOutput()
	if e != nil {
		lower := strings.ToLower(string(b))
		reason := "command failed"
		for _, rule := range [][2]string{{"apparmor", "container AppArmor is unavailable or denied; use a clean VM with Docker support"}, {"permission denied", "required file/kernel permission denied"}, {"address already in use", "selected port is already occupied"}, {"port is already allocated", "selected port is already allocated"}, {"unhealthy", "owned container failed health verification"}, {"no such file or directory", "required runtime file is missing"}, {"network is unreachable", "outbound network is unavailable"}, {"toomanyrequests", "image registry rate limit reached"}, {"failed to resolve", "image registry download could not be resolved"}, {"mount", "container data mount failed"}} {
			if strings.Contains(lower, rule[0]) {
				reason = rule[1]
				break
			}
		}
		return nil, fmt.Errorf("%s: %s; run doctor for the redacted state", program, reason)
	}
	return b, nil
}

type Installer struct {
	Run      Runner
	Progress func(string)
}

// The production build's checkpoint cannot inject a fault; CI opts into a separate build tag.
func Checkpoint(point string) error { return installationFault(point) }

func New() *Installer { return &Installer{Run: Run, Progress: func(s string) { fmt.Println(s) }} }
func Validate(c config.Config) error {
	if c.Language != "en" && c.Language != "fa" {
		return errors.New("language must be en or fa")
	}
	if c.Profile != "standard" && c.Profile != "strict" {
		return errors.New("profile must be standard or strict")
	}
	if net.ParseIP(c.Bind) == nil {
		return errors.New("bind must be an IP address")
	}
	if c.PublicURL != "" {
		u, e := url.Parse(c.PublicURL)
		if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
			return errors.New("public_url must be an HTTPS origin")
		}
	}
	if c.Mode != "controller" && c.Mode != "node" {
		return errors.New("mode must be controller or node")
	}
	if c.Port < 1 || c.Port > 65535 {
		return errors.New("port must be between 1 and 65535")
	}
	for _, p := range []string{c.Dir, c.ConfigDir, c.DataDir} {
		clean := filepath.Clean(p)
		if !filepath.IsAbs(p) || clean == "/" || clean == "/etc" || clean == "/usr" || clean == "/var" || strings.ContainsAny(p, "\n\r\x00") {
			return errors.New("choose an absolute dedicated directory")
		}
	}
	if c.Mode == "controller" {
		if c.TLS == "proxy" && c.Bind != "127.0.0.1" && c.Bind != "::1" {
			return errors.New("proxy mode must bind to loopback; set --bind 127.0.0.1")
		}
		if !regexp.MustCompile(`^[a-zA-Z0-9.-]+$`).MatchString(c.Domain) || len(c.Domain) > 253 {
			return errors.New("enter a domain or IPv4 address")
		}
		if c.TLS != "self-signed" && c.TLS != "existing" && c.TLS != "proxy" && c.TLS != "acme-http" && c.TLS != "acme-dns" {
			return errors.New("TLS mode invalid")
		}
	}
	return nil
}
func Preflight(c config.Config) []string {
	checks := OSAndMemory()
	checks = append(checks, DiskCheck(c.Dir)...)
	if runtime.GOOS != "linux" {
		checks = append(checks, "FAIL: Linux required")
	}
	if os.Geteuid() != 0 {
		checks = append(checks, "FAIL: run with sudo or root")
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		checks = append(checks, "FAIL: unsupported CPU architecture")
	}
	if c.Mode == "controller" {
		ctx, done := context.WithTimeout(context.Background(), 8*time.Second)
		defer done()
		if _, e := Run(ctx, "docker", []string{"compose", "version"}, nil); e != nil {
			checks = append(checks, "FAIL: Docker/Compose unavailable; use the official signed apt installer")
		}
		if b, e := Run(ctx, "docker", []string{"inspect", "--format", "{{index .Config.Labels \"com.docker.compose.project.working_dir\"}}", "tunnelmanager-edge"}, nil); e == nil {
			owner := strings.TrimSpace(string(b))
			if owner != "" && filepath.Clean(owner) != filepath.Clean(c.Dir) {
				checks = append(checks, "FAIL: another controller owns the explicit container namespace; repair that directory or uninstall it first")
			}
		}
		owned, e := config.Load(filepath.Join(c.Dir, "installation.json"))
		if e != nil || owned.Port != c.Port || owned.Bind != c.Bind {
			ln, e := net.Listen("tcp", net.JoinHostPort(c.Bind, fmt.Sprint(c.Port)))
			if e != nil {
				checks = append(checks, "FAIL: chosen port occupied; inspect ss -ltnp and choose another port or explicitly free the previous panel site")
			} else {
				ln.Close()
			}
		}
	}
	if _, e := exec.LookPath("systemctl"); e != nil {
		checks = append(checks, "WARN: systemd absent; native agents require it")
	}
	if len(checks) == 0 {
		checks = append(checks, "PASS: Linux/root/architecture/Docker/Compose/port")
	}
	return checks
}
func (i *Installer) Compose(ctx context.Context, c config.Config, args []string, input io.Reader) ([]byte, error) {
	cmd := append([]string{"compose", "--env-file", filepath.Join(c.Dir, ".env"), "-f", filepath.Join(c.Dir, "compose.yaml")}, args...)
	return i.Run(ctx, "docker", cmd, input)
}
func CopyFile(src, dst string, mode os.FileMode) error {
	b, e := os.ReadFile(src)
	if e != nil {
		return e
	}
	return config.Atomic(dst, b, mode)
}
func CopyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, entry os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		rel, e := filepath.Rel(src, path)
		if e != nil {
			return e
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("symlink refused in protected config")
		}
		target := filepath.Join(dst, rel)
		if entry.IsDir() {
			return os.MkdirAll(target, 0700)
		}
		return CopyFile(path, target, 0600)
	})
}
func Snapshot(c config.Config) (string, error) {
	dest := filepath.Join(c.Dir, ".runtime", "snapshots", time.Now().UTC().Format("20060102T150405.000000000"))
	if e := os.MkdirAll(dest, 0700); e != nil {
		return "", e
	}
	for _, f := range []string{"compose.yaml", "nginx.conf", "Dockerfile", "tunnelmanager", ".env", "installation.json"} {
		if _, e := os.Stat(filepath.Join(c.Dir, f)); e == nil {
			if e = CopyFile(filepath.Join(c.Dir, f), filepath.Join(dest, f), 0600); e != nil {
				return "", e
			}
		}
	}
	if e := CopyTree(c.ConfigDir, filepath.Join(dest, "config")); e != nil && !os.IsNotExist(e) {
		return "", e
	}
	return dest, nil
}
func RestoreSnapshot(c config.Config, path string) error {
	for _, f := range []string{"compose.yaml", "nginx.conf", "Dockerfile", "tunnelmanager", ".env", "installation.json"} {
		src := filepath.Join(path, f)
		if _, e := os.Stat(src); e == nil {
			mode := os.FileMode(0600)
			if f == "tunnelmanager" {
				mode = 0755
			}
			if e = CopyFile(src, filepath.Join(c.Dir, f), mode); e != nil {
				return e
			}
		}
	}
	return CopyTree(filepath.Join(path, "config"), c.ConfigDir)
}
func (i *Installer) Setup(ctx context.Context, c config.Config, password string, saveCredentials bool) (err error) {
	if e := Validate(c); e != nil {
		return e
	}
	if c.Mode != "controller" {
		return errors.New("use node enrollment setup")
	}
	for _, check := range Preflight(c) {
		i.Progress(check)
		if strings.HasPrefix(check, "FAIL") {
			return errors.New("preflight failed; nothing installed")
		}
	}
	_, existsErr := os.Stat(filepath.Join(c.Dir, "installation.json"))
	existing := existsErr == nil
	if existing {
		old, e := config.Load(filepath.Join(c.Dir, "installation.json"))
		if e != nil {
			return errors.New("existing installation marker invalid; existing data preserved")
		}
		if filepath.Clean(old.ConfigDir) != filepath.Clean(c.ConfigDir) || filepath.Clean(old.DataDir) != filepath.Clean(c.DataDir) {
			return errors.New("runtime/data relocation requires a verified backup and explicit restore into a fresh installation; existing directories preserved")
		}
	}
	os.MkdirAll(c.Dir, 0700)
	os.MkdirAll(c.ConfigDir, 0700)
	if e := os.MkdirAll(filepath.Join(c.ConfigDir, "migration-backups"), 0700); e != nil {
		return errors.New("migration backup directory unavailable")
	}
	snapshot, e := Snapshot(c)
	if e != nil {
		return e
	}
	if existing {
		// Kept-data uninstall can leave the stack stopped; start only its own DB before backup.
		if _, e = i.Compose(ctx, c, []string{"up", "-d", "--wait", "--wait-timeout", "120", "db"}, nil); e != nil {
			return errors.New("owned database could not start for the protected snapshot")
		}
		if _, e = i.Compose(ctx, c, []string{"stop", "controller", "edge"}, nil); e != nil {
			return e
		}
		dump, e := i.Compose(ctx, c, []string{"exec", "-T", "db", "pg_dump", "-U", "tunnelmanager", "-Fc", "tunnelmanager"}, nil)
		if e != nil {
			i.Compose(ctx, c, []string{"up", "-d", "--wait"}, nil)
			return errors.New("pre-upgrade database backup failed")
		}
		if e = config.Atomic(filepath.Join(snapshot, "database.dump"), dump, 0600); e != nil {
			i.Compose(ctx, c, []string{"up", "-d", "--wait"}, nil)
			return e
		}
	}
	defer func() {
		if err == nil {
			return
		}
		i.Progress("Failed. Restoring owned files and controller.")
		if existing {
			if e := RestoreSnapshot(c, snapshot); e != nil {
				err = errors.New("rollback files failed; protected snapshot preserved")
				return
			}
			i.Compose(ctx, c, []string{"stop", "controller", "edge"}, nil)
			if dump, e := os.ReadFile(filepath.Join(snapshot, "database.dump")); e == nil {
				if _, e = i.Compose(ctx, c, []string{"exec", "-T", "db", "pg_restore", "-U", "tunnelmanager", "-d", "tunnelmanager", "--clean", "--if-exists", "--single-transaction", "--no-owner", "--no-acl"}, strings.NewReader(string(dump))); e != nil {
					err = errors.New("database rollback failed; controller kept stopped")
					return
				}
			}
			if _, e := i.Compose(ctx, c, []string{"up", "-d", "--build", "--force-recreate", "--wait", "--wait-timeout", "120"}, nil); e != nil {
				err = errors.New("rollback health failed; snapshot preserved")
			}
		} else {
			i.Compose(ctx, c, []string{"down"}, nil)
			i.Progress("Owned containers stopped; data preserved for repair.")
		}
	}()
	i.Progress("Step 1 of 5: preserving keys and database")
	if _, e = os.Stat(filepath.Join(c.ConfigDir, "master.key")); os.IsNotExist(e) {
		key := make([]byte, 32)
		rand.Read(key)
		if e = config.Atomic(filepath.Join(c.ConfigDir, "master.key"), key, 0600); e != nil {
			return e
		}
	}
	if _, e = os.Stat(filepath.Join(c.ConfigDir, "db-password")); os.IsNotExist(e) {
		if e = config.Atomic(filepath.Join(c.ConfigDir, "db-password"), []byte(secure.Token(32)), 0600); e != nil {
			return e
		}
	}
	os.MkdirAll(filepath.Join(c.ConfigDir, "policy"), 0700)
	policy, _ := json.Marshal(map[string]string{"profile": c.Profile})
	if e = config.Atomic(filepath.Join(c.ConfigDir, "policy", "desired.json"), policy, 0600); e != nil {
		return e
	}
	i.Progress("Step 2 of 5: TLS and deployment files")
	if e = PrepareData(c, existing); e != nil {
		return e
	}
	if e = i.TLS(ctx, c); e != nil {
		return e
	}
	for _, f := range []string{"compose.yaml", "nginx.conf", "Dockerfile", ".dockerignore"} {
		b, e := deploy.Templates.ReadFile("templates/" + f)
		if e != nil {
			return e
		}
		if c.TLS == "proxy" && f == "nginx.conf" {
			str := strings.Replace(string(b), "listen 9443 ssl;", "listen 9443;", 1)
			for _, line := range []string{"ssl_certificate /tls/cert.pem;", "ssl_certificate_key /tls/key.pem;", "ssl_protocols TLSv1.2 TLSv1.3;"} {
				str = strings.Replace(str, line, "", 1)
			}
			b = []byte(str)
		}
		if c.TLS == "proxy" && f == "compose.yaml" {
			str := strings.Replace(string(b), "command: [edge]", "command: [edge, --plain]", 1)
			str = strings.Replace(str, "test: [CMD, /tunnelmanager, healthcheck, --url, \"https://127.0.0.1:9443/healthz\", --ca, /tls/cert.pem, --server-name, \"${TUNNELMANAGER_DOMAIN:-localhost}\"]", "test: [CMD, /tunnelmanager, healthcheck, --url, \"http://127.0.0.1:9443/healthz\"]", 1)
			b = []byte(str)
		}
		if e = config.Atomic(filepath.Join(c.Dir, f), b, 0600); e != nil {
			return e
		}
	}
	env := fmt.Sprintf("TUNNELMANAGER_CONFIG_DIR=%s\nTUNNELMANAGER_PORT=%d\nTUNNELMANAGER_BIND=%s\nTUNNELMANAGER_DOMAIN=%s\nTUNNELMANAGER_DATA_DIR=%s\n", c.ConfigDir, c.Port, c.Bind, c.Domain, c.DataDir)
	if e = config.Atomic(filepath.Join(c.Dir, ".env"), []byte(env), 0600); e != nil {
		return e
	}
	containerCfg := c
	containerCfg.ConfigDir = "/config"
	containerCfg.Database = "db"
	if e = config.Write(filepath.Join(c.ConfigDir, "controller.json"), containerCfg); e != nil {
		return e
	}
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	if e = CopyFile(exe, filepath.Join(c.Dir, "tunnelmanager"), 0755); e != nil {
		return e
	}
	i.Progress("Step 3 of 5: isolated controller stack")
	if existing {
		var oldCompose []byte
		oldCompose, _ = os.ReadFile(filepath.Join(snapshot, "compose.yaml"))
		if !strings.Contains(string(oldCompose), "tunnelmanager-postgres-data") {
			if _, e = i.Compose(ctx, c, []string{"up", "-d", "--force-recreate", "--wait", "db"}, nil); e != nil {
				return e
			}
			dump, e := os.ReadFile(filepath.Join(snapshot, "database.dump"))
			if e != nil {
				return e
			}
			if _, e = i.Compose(ctx, c, []string{"exec", "-T", "db", "pg_restore", "-U", "tunnelmanager", "-d", "tunnelmanager", "--clean", "--if-exists", "--single-transaction", "--no-owner", "--no-acl"}, strings.NewReader(string(dump))); e != nil {
				return errors.New("data-location migration failed; old volume retained")
			}
			i.Progress("Database moved to the configured data directory; old Docker volume retained for rollback.")
		}
	}
	if _, e = i.Compose(ctx, c, []string{"up", "-d", "--build", "--force-recreate", "--wait", "--wait-timeout", "180"}, nil); e != nil {
		return e
	}
	if e = installationFault("after-start"); e != nil {
		return e
	}
	i.Progress("Step 4 of 5: account and health")
	if !existing {
		if len(password) < 16 {
			return errors.New("admin password must be at least 16 characters")
		}
		payload, _ := json.Marshal(map[string]string{"Username": c.Admin, "Password": password})
		if _, e = i.Compose(ctx, c, []string{"exec", "-T", "controller", "/tunnelmanager", "bootstrap-admin", "--config", "/config/controller.json"}, strings.NewReader(string(payload))); e != nil {
			return errors.New("admin initialization failed; use repair")
		}
	}
	if _, e = i.Compose(ctx, c, []string{"exec", "-T", "controller", "/tunnelmanager", "healthcheck"}, nil); e != nil {
		return e
	}
	if e = config.Write(filepath.Join(c.Dir, "installation.json"), c); e != nil {
		return e
	}
	if saveCredentials && !existing {
		if e = config.Atomic(filepath.Join(c.ConfigDir, "credentials.once"), []byte("Username: "+c.Admin+"\nPassword: "+password+"\nFirst login: enroll TOTP.\n"), 0600); e != nil {
			return e
		}
	}
	i.Progress("Step 5 of 5: " + c.Origin())
	if c.TLS == "self-signed" {
		i.Progress("Self-signed TLS: trust the public certificate or configure a publicly trusted certificate before general access.")
	}
	i.Progress("Next: tunnelmanager status; tunnelmanager doctor; first login enrolls TOTP.")
	return nil
}
func (i *Installer) TLS(ctx context.Context, c config.Config) error {
	dir := filepath.Join(c.ConfigDir, "tls")
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	if c.TLS == "proxy" {
		return nil
	}
	if c.TLS == "existing" {
		cert, e := os.ReadFile(c.Cert)
		if e != nil {
			return errors.New("certificate unavailable")
		}
		key, e := os.ReadFile(c.Key)
		if e != nil {
			return errors.New("private key unavailable")
		}
		if e = VerifyCertificate(cert, key, c.Domain); e != nil {
			return e
		}
		if e = config.Atomic(filepath.Join(dir, "cert.pem"), cert, 0600); e != nil {
			return e
		}
		return config.Atomic(filepath.Join(dir, "key.pem"), key, 0600)
	}
	if c.TLS == "acme-http" || c.TLS == "acme-dns" {
		return i.ACME(ctx, c)
	}
	if _, e := os.Stat(filepath.Join(dir, "cert.pem")); e == nil {
		cert, _ := os.ReadFile(filepath.Join(dir, "cert.pem"))
		key, _ := os.ReadFile(filepath.Join(dir, "key.pem"))
		return VerifyCertificate(cert, key, c.Domain)
	}
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		return e
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	cert := x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: c.Domain}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	if ip := net.ParseIP(c.Domain); ip != nil {
		cert.IPAddresses = []net.IP{ip}
	} else {
		cert.DNSNames = []string{c.Domain}
	}
	der, e := x509.CreateCertificate(rand.Reader, &cert, &cert, &key.PublicKey, key)
	if e != nil {
		return e
	}
	if e = config.Atomic(filepath.Join(dir, "cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); e != nil {
		return e
	}
	return config.Atomic(filepath.Join(dir, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0600)
}
func VerifyCertificate(cert, key []byte, domain string) error {
	pair, e := tls.X509KeyPair(cert, key)
	if e != nil {
		return errors.New("certificate and key mismatch")
	}
	c, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		return errors.New("invalid certificate")
	}
	if e = c.VerifyHostname(domain); e != nil {
		return errors.New("certificate does not cover panel domain")
	}
	if time.Now().Before(c.NotBefore) || time.Until(c.NotAfter) < 24*time.Hour {
		return errors.New("certificate expired or near expiry")
	}
	return nil
}
func Fetch(ctx context.Context, url string, max int64) ([]byte, error) {
	r, e := http.NewRequestWithContext(ctx, "GET", url, nil)
	if e != nil {
		return nil, e
	}
	client := http.Client{Timeout: 45 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" || len(via) > 5 {
			return errors.New("unsafe redirect")
		}
		return nil
	}}
	resp, e := client.Do(r)
	if e != nil {
		return nil, errors.New("download unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, errors.New("download rejected")
	}
	b, e := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if int64(len(b)) > max {
		return nil, errors.New("download too large")
	}
	return b, e
}
