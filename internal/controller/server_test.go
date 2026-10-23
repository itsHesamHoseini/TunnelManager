package controller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/itsHesamHoseini/TunnelManager/internal/secure"
	"github.com/jackc/pgx/v5/pgxpool"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func testServer(t *testing.T) (*Server, *httptest.Server, *http.Client) {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL unavailable; native PostgreSQL integration untested")
	}
	ctx := context.Background()
	pool, e := pgxpool.New(ctx, url)
	if e != nil {
		t.Fatal("database unavailable")
	}
	schema := fmt.Sprintf("tm_test_%d", time.Now().UnixNano())
	if _, e = pool.Exec(ctx, "CREATE SCHEMA "+schema); e != nil {
		t.Fatal("test schema unavailable")
	}
	cfg, e := pgxpool.ParseConfig(url)
	if e != nil {
		t.Fatal("invalid test database config")
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	cfg.MaxConns = 6
	p, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := schemaFS()
	if _, e = p.Exec(ctx, b); e != nil {
		t.Fatal(e)
	}
	s := &Server{Config: Config{Key: make([]byte, 32), Static: testUI()}, DB: p, Limiter: newLimiter(), dummy: secure.Password("synthetic-dummy-password"), passwordSlots: make(chan struct{}, 2), agentSlots: make(chan struct{}, 8), connected: emptyConnections(), settings: Settings{Language: "en", Profile: "standard"}}
	s.bootstrapSlots = make(chan struct{}, 1)
	if e = s.InitAdmin(ctx, "testadmin", "Synthetic-Password-2026!"); e != nil {
		t.Fatal(e)
	}
	srv := httptest.NewUnstartedServer(s.Handler())
	srv.Listener.Close()
	// Some Windows hosts allocate ephemeral ports in Chromium's blocked range
	// (for example 6665). Bind an ordinary high loopback port, without changing
	// browser protections or the production listener.
	for i := 0; i < 100; i++ {
		port := 20000 + (time.Now().UnixNano()+int64(i))%40000
		listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			srv.Listener = listener
			break
		}
		if i == 99 {
			t.Fatal("test loopback port unavailable")
		}
	}
	srv.StartTLS()
	s.Config.Origin = srv.URL
	c := srv.Client()
	c.Jar, _ = cookiejar.New(nil)
	t.Cleanup(func() { srv.Close(); s.Close(); pool.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE"); pool.Close() })
	return s, srv, c
}
func request(t *testing.T, c *http.Client, url, method string, body any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	r, e := http.NewRequest(method, url, bytes.NewReader(b))
	if e != nil {
		t.Fatal(e)
	}
	r.Header.Set("Content-Type", "application/json")
	resp, e := c.Do(r)
	if e != nil {
		t.Fatal(e)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var v map[string]any
	json.Unmarshal(data, &v)
	return resp.StatusCode, v
}
func enrollMFA(t *testing.T, srv *httptest.Server, c *http.Client) []any {
	status, b := request(t, c, srv.URL+"/api/login", "POST", map[string]string{"Username": "testadmin", "Password": "Synthetic-Password-2026!"})
	if status != 200 || b["next"] != "enroll" {
		t.Fatal(status, b)
	}
	status, b = request(t, c, srv.URL+"/api/mfa/enroll", "GET", nil)
	if status != 200 {
		t.Fatal(status)
	}
	secret := b["secret"].(string)
	status, b = request(t, c, srv.URL+"/api/mfa/enroll", "POST", map[string]string{"Code": secure.Code(secret, time.Now().Unix()/30)})
	if status != 200 {
		t.Fatal(status, b)
	}
	return b["recovery_codes"].([]any)
}
func TestAuthMFARecoveryAndRevocation(t *testing.T) {
	s, srv, c := testServer(t)
	status, _ := request(t, c, srv.URL+"/api/me", "GET", nil)
	if status != 401 {
		t.Fatal("private data leaked")
	}
	codes := enrollMFA(t, srv, c)
	status, _ = request(t, c, srv.URL+"/api/me", "GET", nil)
	if status != 200 {
		t.Fatal("MFA session missing")
	}
	request(t, c, srv.URL+"/api/logout", "POST", nil)
	request(t, c, srv.URL+"/api/login", "POST", map[string]string{"Username": "testadmin", "Password": "Synthetic-Password-2026!"})
	status, _ = request(t, c, srv.URL+"/api/mfa", "POST", map[string]string{"method": "recovery", "code": codes[0].(string)})
	if status != 200 {
		t.Fatal("recovery failed")
	}
	request(t, c, srv.URL+"/api/logout", "POST", nil)
	request(t, c, srv.URL+"/api/login", "POST", map[string]string{"Username": "testadmin", "Password": "Synthetic-Password-2026!"})
	status, _ = request(t, c, srv.URL+"/api/mfa", "POST", map[string]string{"method": "recovery", "code": codes[0].(string)})
	if status != 401 {
		t.Fatal("recovery replay accepted")
	}
	var count int
	s.DB.QueryRow(context.Background(), "SELECT count(*) FROM audit WHERE action='login' AND result='success'").Scan(&count)
	if count != 2 {
		t.Fatal("missing audit")
	}
}
func TestUnknownUserAndLockout(t *testing.T) {
	s, srv, c := testServer(t)
	_, known := request(t, c, srv.URL+"/api/login", "POST", map[string]string{"Username": "testadmin", "Password": "wrong"})
	_, unknown := request(t, c, srv.URL+"/api/login", "POST", map[string]string{"Username": "nobody", "Password": "wrong"})
	if known["message"] != unknown["message"] {
		t.Fatal("username disclosure")
	}
	for i := 0; i < 4; i++ {
		s.DB.Exec(context.Background(), "UPDATE auth_failures SET until_time=now()-interval '1 second'")
		s.Limiter = newLimiter()
		request(t, c, srv.URL+"/api/login", "POST", map[string]string{"Username": "testadmin", "Password": "wrong"})
	}
	s.Limiter = newLimiter()
	status, _ := request(t, c, srv.URL+"/api/login", "POST", map[string]string{"Username": "testadmin", "Password": "Synthetic-Password-2026!"})
	if status != 429 {
		t.Fatal("lockout absent", status)
	}
}
func TestEnrollmentConsumedOnce(t *testing.T) {
	s, srv, c := testServer(t)
	token, e := s.CreateEnrollment(context.Background(), "Example node", "iran", false)
	if e != nil {
		t.Fatal(e)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	payload := map[string]string{"token": token, "public_key": base64.RawURLEncoding.EncodeToString(pub)}
	var wg sync.WaitGroup
	var mu sync.Mutex
	success := 0
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			status, _ := request(t, c, srv.URL+"/api/enroll", "POST", payload)
			if status == 200 {
				mu.Lock()
				success++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if success != 1 {
		t.Fatal("token reused", success)
	}
	var approved bool
	s.DB.QueryRow(context.Background(), "SELECT approved FROM nodes LIMIT 1").Scan(&approved)
	if approved {
		t.Fatal("automatic adoption")
	}
}
func TestOriginAndOversize(t *testing.T) {
	_, srv, c := testServer(t)
	r, _ := http.NewRequest("POST", srv.URL+"/api/login", strings.NewReader("{}"))
	r.Header.Set("Origin", "https://example.net")
	resp, _ := c.Do(r)
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatal("foreign origin accepted")
	}
	status, _ := request(t, c, srv.URL+"/api/login", "POST", map[string]string{"Username": strings.Repeat("x", 70000)})
	if status != 400 {
		t.Fatal("oversize accepted", status)
	}
}
