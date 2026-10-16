package controller

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
)

var providerHTTP = &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("provider_redirect_refused") }}
var zonePattern = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)

func providerDNS(ctx context.Context, token, method, path string, payload any) (json.RawMessage, error) {
	body, _ := json.Marshal(payload)
	req, e := http.NewRequestWithContext(ctx, method, "https://api.cloudflare.com/client/v4/"+path, bytes.NewReader(body))
	if e != nil {
		return nil, errors.New("dns_provider_request_invalid")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, e := providerHTTP.Do(req)
	if e != nil {
		return nil, errors.New("dns_provider_network_unavailable")
	}
	defer resp.Body.Close()
	var out struct {
		Success bool            `json:"success"`
		Result  json.RawMessage `json:"result"`
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || json.NewDecoder(io.LimitReader(resp.Body, 65536)).Decode(&out) != nil || !out.Success {
		return nil, errors.New("dns_provider_rejected_check_zone_and_scoped_token")
	}
	return out.Result, nil
}
func signingKey(value string) (crypto.Signer, string, error) {
	if value != "" {
		block, _ := pem.Decode([]byte(value))
		if block == nil {
			return nil, "", errors.New("account_key_unreadable")
		}
		key, e := x509.ParsePKCS8PrivateKey(block.Bytes)
		if e != nil {
			return nil, "", e
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, "", errors.New("invalid_account_key")
		}
		return signer, value, nil
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, "", e
	}
	der, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return nil, "", e
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}
func (s *Server) issueACME(parent context.Context, id string, q *CertificateRequest, save func() error) error {
	if !domainRE.MatchString(q.Domain) || !zonePattern.MatchString(q.Zone) || len(q.ProviderToken) < 20 || len(q.ProviderToken) > 250 || !q.AcceptTerms {
		return errors.New("acme_requires_domain_zone_scoped_dns_token_and_terms")
	}
	if _, e := mail.ParseAddress(q.Email); e != nil {
		return errors.New("acme_email_invalid")
	}
	ctx, cancel := context.WithTimeout(parent, 6*time.Minute)
	defer cancel()
	account, encoded, e := signingKey(q.AccountKey)
	if e != nil {
		return errors.New("acme_account_key_invalid")
	}
	q.AccountKey = encoded
	private, encoded, e := signingKey(q.Key)
	if e != nil {
		return errors.New("certificate_private_key_invalid")
	}
	q.Key = encoded
	if e = save(); e != nil {
		return e
	}
	directory := "https://acme-v02.api.letsencrypt.org/directory"
	if q.Staging {
		directory = "https://acme-staging-v02.api.letsencrypt.org/directory"
	}
	client := acme.Client{Key: account, DirectoryURL: directory, HTTPClient: providerHTTP, UserAgent: "TunnelManager"}
	s.step(ctx, id, "acme.account", "", "running", "")
	if _, e = client.Register(ctx, &acme.Account{Contact: []string{"mailto:" + q.Email}}, acme.AcceptTOS); e != nil {
		return errors.New("acme_account_registration_failed")
	}
	s.step(ctx, id, "acme.account", "", "succeeded", "")
	var order *acme.Order
	if q.OrderURL != "" {
		order, e = client.GetOrder(ctx, q.OrderURL)
	} else {
		order, e = client.AuthorizeOrder(ctx, acme.DomainIDs(q.Domain))
		if e == nil {
			q.OrderURL = order.URI
			e = save()
		}
	}
	if e != nil {
		return errors.New("acme_order_unavailable")
	}
	cleanup := func() error {
		if q.RecordID == "" {
			return nil
		}
		if !zonePattern.MatchString(q.RecordID) {
			return errors.New("dns_cleanup_identity_invalid")
		}
		_, e := providerDNS(context.WithoutCancel(parent), q.ProviderToken, "DELETE", "zones/"+q.Zone+"/dns_records/"+q.RecordID, nil)
		if e == nil {
			q.RecordID = ""
			e = save()
		}
		return e
	}
	for _, authURL := range order.AuthzURLs {
		auth, e := client.GetAuthorization(ctx, authURL)
		if e != nil {
			return errors.New("acme_authorization_unavailable")
		}
		if auth.Status == acme.StatusValid {
			continue
		}
		var challenge *acme.Challenge
		for _, c := range auth.Challenges {
			if c.Type == "dns-01" {
				challenge = c
				break
			}
		}
		if challenge == nil {
			return errors.New("acme_dns_challenge_missing")
		}
		value, e := client.DNS01ChallengeRecord(challenge.Token)
		if e != nil {
			return errors.New("acme_challenge_invalid")
		}
		name := "_acme-challenge." + strings.TrimPrefix(q.Domain, "*.")
		if q.RecordID == "" {
			raw, e := providerDNS(ctx, q.ProviderToken, "POST", "zones/"+q.Zone+"/dns_records", map[string]any{"type": "TXT", "name": name, "content": value, "ttl": 60, "comment": "TunnelManager operation " + id})
			if e != nil {
				return e
			}
			var record struct {
				ID string `json:"id"`
			}
			if json.Unmarshal(raw, &record) != nil || !zonePattern.MatchString(record.ID) {
				return errors.New("dns_record_identity_missing")
			}
			q.RecordID = record.ID
			if e = save(); e != nil {
				return e
			}
		}
		s.step(ctx, id, "dns.propagation", "", "running", "")
		propagated := false
		until := time.Now().Add(2 * time.Minute)
		for time.Now().Before(until) {
			lookupCtx, done := context.WithTimeout(ctx, 3*time.Second)
			records, _ := net.DefaultResolver.LookupTXT(lookupCtx, name)
			done()
			for _, v := range records {
				if v == value {
					propagated = true
				}
			}
			if propagated {
				break
			}
			select {
			case <-ctx.Done():
				cleanup()
				return errors.New("dns_propagation_cancelled")
			case <-time.After(3 * time.Second):
			}
		}
		if !propagated {
			cleanup()
			return errors.New("dns_txt_not_propagated_check_authoritative_nameservers")
		}
		s.step(ctx, id, "dns.propagation", "", "succeeded", "")
		if _, e = client.Accept(ctx, challenge); e != nil {
			cleanup()
			return errors.New("acme_challenge_rejected")
		}
		_, e = client.WaitAuthorization(ctx, authURL)
		cleanupError := cleanup()
		if e != nil {
			return errors.New("acme_dns_validation_failed")
		}
		if cleanupError != nil {
			return errors.New("dns_challenge_cleanup_failed_retry_operation")
		}
	}
	order, e = client.WaitOrder(ctx, q.OrderURL)
	if e != nil {
		return errors.New("acme_order_not_ready")
	}
	csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: q.Domain}, DNSNames: []string{q.Domain}}, private)
	if e != nil {
		return e
	}
	s.step(ctx, id, "acme.issue", "", "running", "")
	der, _, e := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if e != nil {
		return errors.New("acme_certificate_issue_failed")
	}
	var cert bytes.Buffer
	for _, part := range der {
		pem.Encode(&cert, &pem.Block{Type: "CERTIFICATE", Bytes: part})
	}
	q.Cert = cert.String()
	s.step(ctx, id, "acme.issue", "", "succeeded", "")
	return save()
}
