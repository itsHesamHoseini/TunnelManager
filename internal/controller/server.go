package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/coder/websocket"
	"github.com/itsHesamHoseini/TunnelManager/internal/buildinfo"
	"github.com/itsHesamHoseini/TunnelManager/internal/limit"
	"github.com/itsHesamHoseini/TunnelManager/internal/secure"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/skip2/go-qrcode"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed schema.sql
var schema embed.FS

type Config struct {
	PolicyDirectory              string
	Language                     string
	Address, Origin, DatabaseURL string
	Key                          []byte
	TrustProxy                   bool
	Static                       http.Handler
	Profile                      string
}
type Settings struct {
	AlertOfflineSeconds  int      `json:"alert_offline_seconds"`
	AlertCertificateDays int      `json:"alert_certificate_days"`
	AlertRepeatMinutes   int      `json:"alert_repeat_minutes"`
	RetentionDays        int      `json:"retention_days"`
	Language             string   `json:"language"`
	Theme                string   `json:"theme"`
	AccessOnly           []string `json:"access_only"`
	Trusted              []string `json:"trusted"`
	Profile              string   `json:"profile"`
	TelegramToken        string   `json:"telegram_token,omitempty"`
	ChatID               string   `json:"chat_id,omitempty"`
	TelegramEnabled      bool     `json:"telegram_enabled"`
	TelegramAlerts       bool     `json:"telegram_alerts"`
	TelegramOperations   bool     `json:"telegram_operations"`
}
type Server struct {
	Config        Config
	DB            *pgxpool.Pool
	Limiter       *limit.Limiter
	dummy         string
	passwordSlots chan struct{}
	agentSlots    chan struct{}
	mu            sync.Mutex
	connected     map[string]*websocket.Conn
	settings      Settings
}

func New(ctx context.Context, cfg Config) (*Server, error) {
	pc, e := pgxpool.ParseConfig(cfg.DatabaseURL)
	if e != nil {
		return nil, errors.New("database configuration invalid")
	}
	pc.MaxConns = 6
	p, e := pgxpool.NewWithConfig(ctx, pc)
	if e != nil {
		return nil, e
	}
	b, _ := schema.ReadFile("schema.sql")
	if _, e = p.Exec(ctx, string(b)); e != nil {
		p.Close()
		return nil, e
	}
	if len(cfg.Key) != 32 {
		p.Close()
		return nil, errors.New("master key must be 32 bytes")
	}
	defaults := Settings{Language: "en", Profile: "standard", RetentionDays: 30}
	if cfg.Language == "fa" {
		defaults.Language = "fa"
	}
	if cfg.Profile == "strict" {
		defaults.Profile = "strict"
	}
	s := &Server{Config: cfg, DB: p, Limiter: limit.New(), dummy: secure.Password(secure.Token(32)), passwordSlots: make(chan struct{}, 2), agentSlots: make(chan struct{}, 8), connected: map[string]*websocket.Conn{}, settings: defaults}
	var encrypted []byte
	if e = p.QueryRow(ctx, "SELECT encrypted FROM settings WHERE id=1").Scan(&encrypted); e == nil {
		b, e = secure.Open(cfg.Key, "settings", encrypted)
		if e != nil {
			return nil, errors.New("settings decryption failed")
		}
		if e = json.Unmarshal(b, &s.settings); e != nil {
			return nil, e
		}
	}
	s.syncEdgeProfile()
	return s, nil
}

func (s *Server) syncEdgeProfile() error {
	if s.Config.PolicyDirectory == "" {
		return nil
	}
	st := s.settingsCopy()
	b, _ := json.Marshal(map[string]string{"profile": st.Profile})
	return runtimeConfigAtomic(filepath.Join(s.Config.PolicyDirectory, "desired.json"), b)
}
func (s *Server) Close() {
	s.mu.Lock()
	for _, c := range s.connected {
		c.CloseNow()
	}
	s.mu.Unlock()
	s.DB.Close()
}
func (s *Server) InitAdmin(ctx context.Context, u, p string) error {
	if len(u) < 3 || len(u) > 64 || len(p) < 16 {
		return errors.New("username >=3 and password >=16 characters required")
	}
	tag, e := s.DB.Exec(ctx, "INSERT INTO admins(id,username,password_hash)VALUES(1,$1,$2) ON CONFLICT(id) DO NOTHING", u, secure.Password(p))
	if e != nil {
		return e
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	var existing, hash string
	if e = s.DB.QueryRow(ctx, "SELECT username,password_hash FROM admins WHERE id=1").Scan(&existing, &hash); e != nil {
		return e
	}
	if existing == u && secure.VerifyPassword(p, hash) {
		return nil
	}
	return errors.New("existing administrator retained; use explicit password reset if needed")
}
func (s *Server) Audit(ctx context.Context, a, t, r string) {
	_, _ = s.DB.Exec(ctx, "INSERT INTO audit(action,target,result)VALUES($1,$2,$3)", a, t, r)
}
func write(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, code, en, fa string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"code": code, "message": en, "message_fa": fa})
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 65536)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		fail(w, 400, "invalid_input", "Check the input and try again.", "ورودی را بررسی و دوباره تلاش کنید.")
		return false
	}
	if e := d.Decode(&struct{}{}); e != io.EOF {
		fail(w, 400, "invalid_input", "Send one JSON object.", "یک درخواست معتبر ارسال کنید.")
		return false
	}
	return true
}
func (s *Server) ip(r *http.Request) string {
	if s.Config.TrustProxy {
		if ip := net.ParseIP(r.Header.Get("X-Real-IP")); ip != nil {
			return ip.String()
		}
	}
	h, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil {
		return "unknown"
	}
	return h
}
func (s *Server) settingsCopy() Settings { s.mu.Lock(); defer s.mu.Unlock(); return s.settings }
func inCIDRs(ip string, list []string) bool {
	p := net.ParseIP(ip)
	for _, x := range list {
		if _, n, e := net.ParseCIDR(x); e == nil && n.Contains(p) {
			return true
		}
		if p != nil && p.Equal(net.ParseIP(x)) {
			return true
		}
	}
	return false
}
func (s *Server) limited(w http.ResponseWriter, r *http.Request, key string, rate, burst float64) bool {
	if s.settingsCopy().Profile == "strict" {
		rate /= 2
		burst = math.Max(2, burst/2)
	}
	if d := s.Limiter.Allow(key, rate, burst); d > 0 {
		if s.Limiter.Allow("audit429:"+s.ip(r), 1.0/60, 1) == 0 {
			ctx, cancel := context.WithTimeout(r.Context(), 250*time.Millisecond)
			s.Audit(ctx, "rate-limit", s.ip(r), "throttled")
			cancel()
		}
		w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(d.Seconds()))))
		fail(w, 429, "rate_limited", "Too many attempts. Wait and try again.", "درخواست‌ها زیاد است؛ کمی صبر کنید و دوباره تلاش کنید.")
		return true
	}
	return false
}
func (s *Server) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		ctx, c := context.WithTimeout(r.Context(), 2*time.Second)
		defer c()
		if s.DB.Ping(ctx) != nil {
			fail(w, 503, "not_ready", "Database unavailable.", "پایگاه داده در دسترس نیست.")
			return
		}
		write(w, map[string]any{"ok": true, "version": buildinfo.Version, "commit": buildinfo.Commit})
	})
	m.HandleFunc("GET /api/context", func(w http.ResponseWriter, r *http.Request) {
		st := s.settingsCopy()
		write(w, map[string]any{"name": "TunnelManager", "version": buildinfo.Version, "commit": buildinfo.Commit, "language": st.Language})
	})
	m.HandleFunc("POST /api/login", s.login)
	m.HandleFunc("POST /api/mfa", s.mfa)
	m.HandleFunc("GET /api/mfa/enroll", s.mfaEnroll)
	m.HandleFunc("POST /api/mfa/enroll", s.mfaConfirm)
	m.HandleFunc("POST /api/mfa/telegram", s.telegramRequest)
	m.HandleFunc("POST /api/logout", s.logout)
	m.HandleFunc("POST /api/enroll", s.enroll)
	m.HandleFunc("GET /api/agent", s.agentConnection)
	private := http.NewServeMux()
	private.HandleFunc("GET /api/me", s.me)
	private.HandleFunc("GET /api/sessions", s.sessions)
	private.HandleFunc("DELETE /api/sessions/{hash}", s.revoke)
	private.HandleFunc("GET /api/audit", s.auditList)
	private.HandleFunc("GET /api/settings", s.getSettings)
	private.HandleFunc("PUT /api/settings", s.putSettings)
	private.HandleFunc("POST /api/settings/telegram-test", s.telegramTest)
	private.HandleFunc("GET /api/nodes", s.nodes)
	private.HandleFunc("POST /api/nodes/token", s.nodeToken)
	private.HandleFunc("GET /api/nodes/{id}", s.nodeDetail)
	private.HandleFunc("PUT /api/nodes/{id}", s.nodeUpdate)
	private.HandleFunc("POST /api/nodes/{id}/approve", s.nodeApprove)
	private.HandleFunc("DELETE /api/nodes/{id}", s.nodeDelete)
	private.HandleFunc("GET /api/nodes/{id}/history", s.nodeHistory)
	private.HandleFunc("GET /api/engines", s.engineCatalog)
	private.HandleFunc("GET /api/operations", s.operationList)
	private.HandleFunc("GET /api/operations/{id}", s.operationDetail)
	private.HandleFunc("POST /api/operations/{id}/transition", s.planTransition)
	private.HandleFunc("POST /api/operations/{id}/release", s.recoveryRelease)
	private.HandleFunc("POST /api/operations/{id}/check", s.pendingPlanCheck)
	private.HandleFunc("POST /api/nodes/{id}/actions", s.nodeAction)
	private.HandleFunc("GET /api/nodes/{id}/inventory", s.nodeInventory)
	private.HandleFunc("GET /api/tunnels", s.tunnelList)
	private.HandleFunc("GET /api/tunnels/{id}", s.tunnelDetail)
	private.HandleFunc("POST /api/tunnel-plans", s.tunnelPlan)
	private.HandleFunc("POST /api/tunnels/{id}/actions", s.tunnelAction)
	private.HandleFunc("POST /api/tunnel-actions", s.bulkTunnelAction)
	private.HandleFunc("GET /api/discoveries", s.discoveryList)
	private.HandleFunc("POST /api/tunnel-imports", s.tunnelImport)
	private.HandleFunc("POST /api/tunnels/{id}/adopt", s.tunnelAdopt)
	private.HandleFunc("POST /api/tunnels/{id}/check", s.tunnelCheck)
	private.HandleFunc("GET /api/tunnels/{id}/history", s.tunnelHistory)
	private.HandleFunc("GET /api/alerts", s.alertList)
	private.HandleFunc("GET /api/certificates", s.certificateList)
	private.HandleFunc("POST /api/certificates", s.certificateRequest)
	private.HandleFunc("POST /api/certificates/{id}/deploy", s.certificateDeploy)
	private.HandleFunc("PUT /api/certificates/{id}/policy", s.certificatePolicy)
	private.HandleFunc("PUT /api/alerts/{id}", s.alertUpdate)
	private.HandleFunc("GET /api/nodes/{id}/instances/{instance}/affected", s.instanceAffected)
	m.Handle("/api/", s.auth(private))
	if s.Config.Static != nil {
		m.Handle("/", s.Config.Static)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'")
		w.Header().Set("X-Request-ID", secure.Token(8))
		if len(r.URL.Path) > 512 {
			fail(w, 400, "invalid_path", "Path too long.", "مسیر درخواست معتبر نیست.")
			return
		}
		ip := s.ip(r)
		st := s.settingsCopy()
		if len(st.AccessOnly) > 0 && !inCIDRs(ip, st.AccessOnly) && r.URL.Path != "/healthz" && r.URL.Path != "/api/enroll" && r.URL.Path != "/api/agent" {
			fail(w, 403, "access_denied", "Your address is not in the access list.", "نشانی شما در فهرست دسترسی نیست.")
			return
		}
		if s.limited(w, r, "api-ip:"+ip, 5, 100) {
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" {
			if origin := r.Header.Get("Origin"); origin != "" && origin != s.Config.Origin {
				fail(w, 403, "origin", "Open the panel from its configured address.", "پنل را از نشانی اصلی آن باز کنید.")
				return
			}
		}
		m.ServeHTTP(w, r)
	})
}
func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, e := r.Cookie("tm_session")
		if e != nil {
			fail(w, 401, "login_required", "Sign in first.", "ابتدا وارد شوید.")
			return
		}
		var yes bool
		e = s.DB.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM sessions WHERE hash=$1 AND expires>now())", secure.Hash(c.Value)).Scan(&yes)
		if e != nil || !yes {
			fail(w, 401, "login_required", "Session expired. Sign in again.", "نشست تمام شده؛ دوباره وارد شوید.")
			return
		}
		if s.limited(w, r, "session:"+secure.Hash(c.Value), 3, 60) {
			return
		}
		if r.Method != "GET" && s.limited(w, r, "sensitive:"+secure.Hash(c.Value), .2, 5) {
			return
		}
		next.ServeHTTP(w, r)
	})
}
func (s *Server) cookie(w http.ResponseWriter, name, value string, age int) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: age})
}
func (s *Server) lock(ctx context.Context, key string) time.Duration {
	var t time.Time
	if s.DB.QueryRow(ctx, "SELECT until_time FROM auth_failures WHERE key=$1", key).Scan(&t) == nil && t.After(time.Now()) {
		return time.Until(t)
	}
	return 0
}
func (s *Server) bad(ctx context.Context, key, action string) {
	s.DB.Exec(ctx, `INSERT INTO auth_failures(key,failures,until_time)VALUES($1,1,now()+interval '1 second') ON CONFLICT(key) DO UPDATE SET failures=CASE WHEN auth_failures.updated<now()-interval '15 minutes' THEN 1 ELSE LEAST(auth_failures.failures+1,5) END,until_time=now()+CASE WHEN auth_failures.failures>=4 THEN interval '15 minutes' ELSE interval '1 second'*power(2,LEAST(auth_failures.failures,3)) END,updated=now()`, key)
	s.Audit(ctx, action, "", "denied")
	if s.lock(ctx, key) > time.Minute {
		s.Audit(ctx, "auth-lockout", "", "temporary")
	}
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var q struct{ Username, Password string }
	if !decode(w, r, &q) {
		return
	}
	if len(q.Password) > 1024 || len(q.Username) > 64 {
		fail(w, 400, "invalid_input", "Invalid input.", "ورودی معتبر نیست.")
		return
	}
	ip := s.ip(r)
	key := "user:" + secure.Hash(strings.ToLower(q.Username))
	if s.limited(w, r, "login:"+ip, .1, 5) {
		return
	}
	if !inCIDRs(ip, s.settingsCopy().Trusted) {
		if d := s.lock(r.Context(), key); d > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(d.Seconds()))))
			fail(w, 429, "rate_limited", "Wait before signing in again.", "برای ورود دوباره کمی صبر کنید.")
			return
		}
	}
	select {
	case s.passwordSlots <- struct{}{}:
		defer func() { <-s.passwordSlots }()
	default:
		w.Header().Set("Retry-After", "2")
		fail(w, 429, "busy", "Try again shortly.", "کمی بعد دوباره تلاش کنید.")
		return
	}
	hash := s.dummy
	var secret []byte
	var u string
	e := s.DB.QueryRow(r.Context(), "SELECT username,password_hash,totp FROM admins WHERE id=1").Scan(&u, &hash, &secret)
	valid := secure.VerifyPassword(q.Password, hash)
	if e != nil || !valid || u != q.Username {
		s.bad(r.Context(), key, "login")
		fail(w, 401, "invalid_login", "Sign-in details are invalid.", "اطلاعات ورود صحیح نیست.")
		return
	}
	s.DB.Exec(r.Context(), "DELETE FROM auth_failures WHERE key=$1", key)
	t := secure.Token(32)
	kind := "mfa"
	if len(secret) == 0 {
		kind = "enroll"
	}
	s.DB.Exec(r.Context(), "DELETE FROM challenges WHERE expires<now()")
	_, e = s.DB.Exec(r.Context(), "INSERT INTO challenges(hash,expires,kind,ip,ua)VALUES($1,now()+interval '2 minutes',$2,$3,$4)", secure.Hash(t), kind, ip, short(r.UserAgent(), 256))
	if e != nil {
		fail(w, 503, "busy", "Try again.", "دوباره تلاش کنید.")
		return
	}
	s.cookie(w, "tm_challenge", t, 120)
	write(w, map[string]any{"next": kind, "telegram_available": s.settingsCopy().TelegramEnabled})
}
func short(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
func challenge(r *http.Request) string {
	c, e := r.Cookie("tm_challenge")
	if e != nil {
		return ""
	}
	return secure.Hash(c.Value)
}
func (s *Server) newSession(ctx context.Context, tx pgx.Tx, w http.ResponseWriter, r *http.Request) error {
	t := secure.Token(32)
	if _, e := tx.Exec(ctx, "INSERT INTO sessions(hash,expires,ip,ua)VALUES($1,now()+interval '12 hours',$2,$3)", secure.Hash(t), s.ip(r), short(r.UserAgent(), 256)); e != nil {
		return e
	}
	s.cookie(w, "tm_session", t, 43200)
	s.cookie(w, "tm_challenge", "", -1)
	return nil
}
func (s *Server) mfa(w http.ResponseWriter, r *http.Request) {
	if d := s.lock(r.Context(), "mfa:"+s.ip(r)); d > 0 && !inCIDRs(s.ip(r), s.settingsCopy().Trusted) {
		w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(d.Seconds()))))
		fail(w, 429, "rate_limited", "Wait before trying another code.", "برای آزمون کد بعدی کمی صبر کنید.")
		return
	}
	var q struct {
		Code   string `json:"code"`
		Method string `json:"method"`
	}
	if !decode(w, r, &q) {
		return
	}
	if s.limited(w, r, "mfa:"+s.ip(r), .05, 5) {
		return
	}
	ctx := r.Context()
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return
	}
	defer tx.Rollback(ctx)
	var kind string
	var approved bool
	e = tx.QueryRow(ctx, "SELECT kind,approved FROM challenges WHERE hash=$1 AND expires>now() FOR UPDATE", challenge(r)).Scan(&kind, &approved)
	if e != nil || kind != "mfa" {
		fail(w, 401, "challenge_expired", "Sign in again.", "زمان تأیید تمام شده؛ دوباره وارد شوید.")
		return
	}
	var blob []byte
	var last int64
	e = tx.QueryRow(ctx, "SELECT totp,totp_step FROM admins WHERE id=1 FOR UPDATE").Scan(&blob, &last)
	valid := false
	var step int64
	if e == nil {
		switch q.Method {
		case "telegram":
			valid = approved
		case "recovery":
			var h string
			e = tx.QueryRow(ctx, "UPDATE recovery SET used=true WHERE hash=$1 AND NOT used RETURNING hash", secure.Hash(strings.ToUpper(strings.TrimSpace(q.Code)))).Scan(&h)
			valid = e == nil
		default:
			secret, e := secure.Open(s.Config.Key, "admin:totp", blob)
			if e == nil {
				step, valid = secure.TOTP(string(secret), q.Code, last, time.Now())
				if valid {
					_, e = tx.Exec(ctx, "UPDATE admins SET totp_step=$1 WHERE id=1", step)
					valid = e == nil
				}
			}
		}
	}
	if !valid {
		s.bad(ctx, "mfa:"+s.ip(r), "mfa")
		fail(w, 401, "invalid_mfa", "Code or approval is not valid.", "کد یا تأیید معتبر نیست.")
		return
	}
	tx.Exec(ctx, "DELETE FROM challenges WHERE hash=$1", challenge(r))
	if s.newSession(ctx, tx, w, r) != nil || tx.Commit(ctx) != nil {
		fail(w, 503, "busy", "Try again.", "دوباره تلاش کنید.")
		return
	}
	s.Audit(ctx, "login", "", "success")
	write(w, map[string]bool{"ok": true})
}
func (s *Server) mfaEnroll(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return
	}
	defer tx.Rollback(ctx)
	var blob []byte
	var kind string
	e = tx.QueryRow(ctx, "SELECT kind,secret FROM challenges WHERE hash=$1 AND expires>now() FOR UPDATE", challenge(r)).Scan(&kind, &blob)
	if e != nil || kind != "enroll" {
		fail(w, 401, "login_required", "Sign in again.", "دوباره وارد شوید.")
		return
	}
	secret := ""
	if len(blob) == 0 {
		secret = secure.NewTOTP()
		blob, e = secure.Seal(s.Config.Key, "challenge:"+challenge(r), []byte(secret))
		if e == nil {
			_, e = tx.Exec(ctx, "UPDATE challenges SET secret=$1 WHERE hash=$2", blob, challenge(r))
		}
	} else {
		var b []byte
		b, e = secure.Open(s.Config.Key, "challenge:"+challenge(r), blob)
		secret = string(b)
	}
	if e != nil || tx.Commit(ctx) != nil {
		fail(w, 503, "busy", "Try again.", "دوباره تلاش کنید.")
		return
	}
	uri := "otpauth://totp/TunnelManager:admin?secret=" + url.QueryEscape(secret) + "&issuer=TunnelManager"
	png, _ := qrcode.Encode(uri, qrcode.Medium, 256)
	write(w, map[string]string{"secret": secret, "uri": uri, "qr": "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)})
}
func (s *Server) mfaConfirm(w http.ResponseWriter, r *http.Request) {
	var q struct{ Code string }
	if !decode(w, r, &q) {
		return
	}
	if s.limited(w, r, "mfa-enroll:"+s.ip(r), .05, 5) {
		return
	}
	ctx := r.Context()
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return
	}
	defer tx.Rollback(ctx)
	var blob []byte
	var kind string
	e = tx.QueryRow(ctx, "SELECT kind,secret FROM challenges WHERE hash=$1 AND expires>now() FOR UPDATE", challenge(r)).Scan(&kind, &blob)
	if e != nil || kind != "enroll" {
		fail(w, 401, "challenge_expired", "Sign in again.", "دوباره وارد شوید.")
		return
	}
	b, e := secure.Open(s.Config.Key, "challenge:"+challenge(r), blob)
	step, valid := secure.TOTP(string(b), q.Code, -1, time.Now())
	if e != nil || !valid {
		fail(w, 400, "invalid_code", "Check the authenticator code.", "کد برنامهٔ تأیید هویت را بررسی کنید.")
		return
	}
	encrypted, e := secure.Seal(s.Config.Key, "admin:totp", b)
	if e != nil {
		return
	}
	tag, e := tx.Exec(ctx, "UPDATE admins SET totp=$1,totp_step=$2 WHERE id=1 AND totp IS NULL", encrypted, step)
	if e != nil || tag.RowsAffected() != 1 {
		fail(w, 409, "already_enrolled", "Already enrolled.", "قبلاً ثبت شده است.")
		return
	}
	codes := []string{}
	for i := 0; i < 10; i++ {
		c := strings.ToUpper(secure.Token(9))
		codes = append(codes, c)
		tx.Exec(ctx, "INSERT INTO recovery(hash)VALUES($1)", secure.Hash(c))
	}
	tx.Exec(ctx, "DELETE FROM challenges WHERE hash=$1", challenge(r))
	if s.newSession(ctx, tx, w, r) != nil || tx.Commit(ctx) != nil {
		fail(w, 503, "busy", "Try again.", "دوباره تلاش کنید.")
		return
	}
	s.Audit(ctx, "mfa-enroll", "", "success")
	s.Audit(ctx, "login", "", "success")
	write(w, map[string]any{"ok": true, "recovery_codes": codes})
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, e := r.Cookie("tm_session"); e == nil {
		s.DB.Exec(r.Context(), "DELETE FROM sessions WHERE hash=$1", secure.Hash(c.Value))
	}
	s.cookie(w, "tm_session", "", -1)
	s.cookie(w, "tm_challenge", "", -1)
	write(w, map[string]bool{"ok": true})
}
func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	var u string
	s.DB.QueryRow(r.Context(), "SELECT username FROM admins WHERE id=1").Scan(&u)
	write(w, map[string]string{"username": u})
}
func (s *Server) sessions(w http.ResponseWriter, r *http.Request) {
	rows, e := s.DB.Query(r.Context(), "SELECT hash,created,expires,ip,ua FROM sessions WHERE expires>now() ORDER BY created DESC LIMIT 100")
	if e != nil {
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	c, _ := r.Cookie("tm_session")
	for rows.Next() {
		var h, ip, ua string
		var a, b time.Time
		rows.Scan(&h, &a, &b, &ip, &ua)
		items = append(items, map[string]any{"id": h, "created": a, "expires": b, "ip": ip, "ua": ua, "current": c != nil && h == secure.Hash(c.Value)})
	}
	write(w, items)
}
func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	s.DB.Exec(r.Context(), "DELETE FROM sessions WHERE hash=$1", r.PathValue("hash"))
	s.Audit(r.Context(), "session-revoke", "", "success")
	write(w, map[string]bool{"ok": true})
}
func (s *Server) auditList(w http.ResponseWriter, r *http.Request) {
	rows, e := s.DB.Query(r.Context(), "SELECT a.at,a.action,COALESCE(n.name,t.name,o.name,a.target),a.result FROM audit a LEFT JOIN nodes n ON n.id=a.target LEFT JOIN tunnels t ON t.id=a.target LEFT JOIN operations o ON o.id=a.target ORDER BY a.id DESC LIMIT 100")
	if e != nil {
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var a time.Time
		var b, c, d string
		rows.Scan(&a, &b, &c, &d)
		items = append(items, map[string]any{"at": a, "action": b, "target": c, "result": d})
	}
	write(w, items)
}
func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	st := s.settingsCopy()
	tokenSet := st.TelegramToken != ""
	st.TelegramToken = ""
	observed := map[string]any{}
	if s.Config.PolicyDirectory != "" {
		if b, e := os.ReadFile(filepath.Join(s.Config.PolicyDirectory, "observed.json")); e == nil {
			json.Unmarshal(b, &observed)
		}
	}
	write(w, map[string]any{"settings": st, "telegram_token_set": tokenSet, "edge": observed})
}
func (s *Server) putSettings(w http.ResponseWriter, r *http.Request) {
	var q Settings
	if !decode(w, r, &q) {
		return
	}
	if q.Language != "fa" && q.Language != "en" {
		q.Language = "en"
	}
	if q.Profile != "strict" {
		q.Profile = "standard"
	}
	if q.RetentionDays == 0 {
		q.RetentionDays = 30
	}
	if q.RetentionDays != 7 && q.RetentionDays != 30 && q.RetentionDays != 90 {
		fail(w, 400, "invalid_retention", "Choose 7, 30 or 90 days.", "نگهداری ۷، ۳۰ یا ۹۰ روز را انتخاب کنید.")
		return
	}
	if q.AlertOfflineSeconds == 0 {
		q.AlertOfflineSeconds = 150
	}
	if q.AlertCertificateDays == 0 {
		q.AlertCertificateDays = 14
	}
	if q.AlertRepeatMinutes == 0 {
		q.AlertRepeatMinutes = 60
	}
	if q.AlertOfflineSeconds < 90 || q.AlertOfflineSeconds > 3600 || q.AlertCertificateDays < 1 || q.AlertCertificateDays > 60 || q.AlertRepeatMinutes < 5 || q.AlertRepeatMinutes > 1440 {
		fail(w, 400, "invalid_alert_thresholds", "Review alert durations.", "مدت‌های هشدار را در بازهٔ مشخص‌شده وارد کنید.")
		return
	}
	for _, list := range [][]string{q.AccessOnly, q.Trusted} {
		if len(list) > 50 {
			fail(w, 400, "invalid_allowlist", "At most 50 addresses.", "حداکثر ۵۰ نشانی مجاز است.")
			return
		}
		for _, x := range list {
			if _, _, e := net.ParseCIDR(x); e != nil && net.ParseIP(x) == nil {
				fail(w, 400, "invalid_allowlist", "Use valid IPs or CIDRs.", "IP یا CIDR معتبر وارد کنید.")
				return
			}
		}
	}
	if len(q.AccessOnly) > 0 && !inCIDRs(s.ip(r), q.AccessOnly) {
		fail(w, 400, "would_lock_out", "Keep your current IP in the access list.", "برای حفظ دسترسی، IP فعلی خود را در فهرست نگه دارید.")
		return
	}
	old := s.settingsCopy()
	if q.TelegramToken == "" {
		q.TelegramToken = old.TelegramToken
	}
	if (q.TelegramEnabled || q.TelegramAlerts || q.TelegramOperations) && (q.TelegramToken == "" || q.ChatID == "") {
		fail(w, 400, "telegram_missing", "Enter bot token and chat ID.", "توکن ربات و شناسهٔ گفتگو را وارد کنید.")
		return
	}
	b, _ := json.Marshal(q)
	enc, e := secure.Seal(s.Config.Key, "settings", b)
	if e != nil {
		return
	}
	_, e = s.DB.Exec(r.Context(), "INSERT INTO settings(id,encrypted)VALUES(1,$1) ON CONFLICT(id) DO UPDATE SET encrypted=$1", enc)
	if e != nil {
		fail(w, 503, "busy", "Try again.", "دوباره تلاش کنید.")
		return
	}
	s.mu.Lock()
	s.settings = q
	s.mu.Unlock()
	s.syncEdgeProfile()
	s.Audit(r.Context(), "settings", "", "success")
	s.getSettings(w, r)
}

// Compile-time references used by the channel implementation in nodes.go.
var _ = ed25519.PublicKeySize
var _ = base64.RawURLEncoding
var _ = rand.Reader
var _ = fmt.Sprint
