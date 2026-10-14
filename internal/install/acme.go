package install

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/itsHesamHoseini/TunnelManager/internal/config"
	"golang.org/x/crypto/acme"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func (i *Installer) ACME(ctx context.Context, c config.Config) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	keyPath := filepath.Join(c.ConfigDir, "acme-account.key")
	var account *ecdsa.PrivateKey
	if b, e := os.ReadFile(keyPath); e == nil {
		p, _ := pem.Decode(b)
		if p == nil {
			return errors.New("ACME account invalid")
		}
		k, e := x509.ParseECPrivateKey(p.Bytes)
		if e != nil {
			return errors.New("ACME account invalid")
		}
		account = k
	} else {
		k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			return e
		}
		account = k
		der, _ := x509.MarshalECPrivateKey(k)
		if e = config.Atomic(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0600); e != nil {
			return e
		}
	}
	client := acme.Client{Key: account, DirectoryURL: acme.LetsEncryptURL}
	if _, e := client.Register(ctx, &acme.Account{}, acme.AcceptTOS); e != nil {
		return errors.New("ACME account registration unavailable")
	}
	order, e := client.AuthorizeOrder(ctx, acme.DomainIDs(c.Domain))
	if e != nil {
		return errors.New("ACME order unavailable; verify domain ownership")
	}
	var mu sync.Mutex
	httpValues := map[string]string{}
	var challengeServer *http.Server
	for _, authURL := range order.AuthzURLs {
		auth, e := client.GetAuthorization(ctx, authURL)
		if e != nil {
			return errors.New("ACME authorization unavailable")
		}
		if auth.Status == acme.StatusValid {
			continue
		}
		kind := "http-01"
		if c.TLS == "acme-dns" {
			kind = "dns-01"
		}
		var chall *acme.Challenge
		for _, v := range auth.Challenges {
			if v.Type == kind {
				chall = v
			}
		}
		if chall == nil {
			return errors.New("requested ACME challenge unsupported")
		}
		cleanup := func() {}
		if kind == "http-01" {
			if challengeServer == nil {
				listener, e := net.Listen("tcp", ":80")
				if e != nil {
					return errors.New("HTTP-01 needs free port 80; choose DNS-01 or existing certificate")
				}
				challengeServer = &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					mu.Lock()
					v := httpValues[r.URL.Path]
					mu.Unlock()
					if v == "" {
						http.NotFound(w, r)
						return
					}
					io.WriteString(w, v)
				})}
				go challengeServer.Serve(listener)
				defer challengeServer.Close()
			}
			response, e := client.HTTP01ChallengeResponse(chall.Token)
			if e != nil {
				return e
			}
			mu.Lock()
			httpValues[client.HTTP01ChallengePath(chall.Token)] = response
			mu.Unlock()
		} else {
			record, e := client.DNS01ChallengeRecord(chall.Token)
			if e != nil {
				return e
			}
			cleanup, e = cloudflareTXT(ctx, "_acme-challenge."+c.Domain, record, os.Getenv("TUNNELMANAGER_CLOUDFLARE_TOKEN"))
			if e != nil {
				return e
			}
			defer cleanup()
			ready := false
			deadline := time.Now().Add(2 * time.Minute)
			for time.Now().Before(deadline) {
				records, _ := net.DefaultResolver.LookupTXT(ctx, "_acme-challenge."+c.Domain)
				for _, r := range records {
					if r == record {
						ready = true
					}
				}
				if ready {
					break
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(3 * time.Second):
				}
			}
			if !ready {
				return errors.New("DNS challenge not propagated; check Cloudflare zone and nameservers")
			}
		}
		if _, e = client.Accept(ctx, chall); e != nil {
			return errors.New("ACME challenge rejected")
		}
		if _, e = client.WaitAuthorization(ctx, authURL); e != nil {
			return errors.New("domain validation failed; verify DNS and public challenge reachability")
		}
	}
	order, e = client.WaitOrder(ctx, order.URI)
	if e != nil {
		return errors.New("ACME order not ready")
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return e
	}
	csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: c.Domain}, DNSNames: []string{c.Domain}}, key)
	if e != nil {
		return e
	}
	chain, _, e := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if e != nil {
		return errors.New("certificate issuance failed")
	}
	var cert []byte
	for _, der := range chain {
		cert = append(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	der, _ := x509.MarshalECPrivateKey(key)
	private := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if e = VerifyCertificate(cert, private, c.Domain); e != nil {
		return e
	}
	if e = config.Atomic(filepath.Join(c.ConfigDir, "tls", "cert.pem"), cert, 0600); e != nil {
		return e
	}
	return config.Atomic(filepath.Join(c.ConfigDir, "tls", "key.pem"), private, 0600)
}
func cfRequest(ctx context.Context, path, method, token string, body any) (json.RawMessage, error) {
	if token == "" || strings.ContainsAny(token, "\r\n") {
		return nil, errors.New("Cloudflare token required through protected input")
	}
	b, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(ctx, method, "https://api.cloudflare.com/client/v4"+path, bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	client := http.Client{Timeout: 15 * time.Second}
	resp, e := client.Do(req)
	if e != nil {
		return nil, errors.New("DNS provider unavailable")
	}
	defer resp.Body.Close()
	var v struct {
		Success bool            `json:"success"`
		Result  json.RawMessage `json:"result"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 65536)).Decode(&v) != nil || !v.Success {
		return nil, errors.New("Cloudflare permission/zone request failed")
	}
	return v.Result, nil
}
func cloudflareTXT(ctx context.Context, name, value, token string) (func(), error) {
	labels := strings.Split(strings.TrimPrefix(name, "_acme-challenge."), ".")
	zone := ""
	for i := 0; i < len(labels)-1; i++ {
		b, e := cfRequest(ctx, "/zones?name="+strings.Join(labels[i:], "."), "GET", token, nil)
		if e != nil {
			return nil, e
		}
		var zones []struct {
			ID string `json:"id"`
		}
		json.Unmarshal(b, &zones)
		if len(zones) == 1 {
			zone = zones[0].ID
			break
		}
	}
	if zone == "" {
		return nil, errors.New("Cloudflare zone not found; token needs zone read and DNS edit")
	}
	b, e := cfRequest(ctx, "/zones/"+zone+"/dns_records", "POST", token, map[string]any{"type": "TXT", "name": name, "content": value, "ttl": 120})
	if e != nil {
		return nil, e
	}
	var record struct {
		ID string `json:"id"`
	}
	json.Unmarshal(b, &record)
	if record.ID == "" {
		return nil, errors.New("DNS record result invalid")
	}
	return func() {
		clean, done := context.WithTimeout(context.Background(), 15*time.Second)
		defer done()
		cfRequest(clean, "/zones/"+zone+"/dns_records/"+record.ID, "DELETE", token, nil)
	}, nil
}
