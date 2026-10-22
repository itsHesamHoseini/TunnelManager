package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCertificateIssueAndEncryptedPersistence(t *testing.T) {
	s, _, _ := testServer(t)
	ctx := context.Background()
	q := CertificateRequest{Name: "Synthetic TLS", Domain: "transport.example.com", Method: "self-signed", Days: 3}
	payload, _ := json.Marshal(q)
	id, e := s.newJob(ctx, "cert_request", "certificate", "cert1", q.Name, JobPayload{Kind: "issue", Certificate: "cert1", Payload: payload})
	if e != nil {
		t.Fatal(e)
	}
	s.processJob(ctx, id)
	var phase string
	s.DB.QueryRow(ctx, "SELECT phase FROM operations WHERE id=$1", id).Scan(&phase)
	if phase != "succeeded" {
		t.Fatal("certificate issuance not completed")
	}
	got, rev, e := s.readCertificate(ctx, "cert1")
	if e != nil || rev != 1 || got.Key == "" {
		t.Fatal("protected certificate absent")
	}
	leaf, e := validateCertificate(got)
	if e != nil || leaf.VerifyHostname(q.Domain) != nil {
		t.Fatal("certificate invalid")
	}
	var cipher []byte
	s.DB.QueryRow(ctx, "SELECT cipher FROM certificates WHERE id='cert1'").Scan(&cipher)
	if bytes.Contains(cipher, []byte(got.Key)) {
		t.Fatal("private certificate material stored in plaintext")
	}
	got.Domain = "different.example.com"
	if _, e = validateCertificate(got); e == nil {
		t.Fatal("hostname mismatch accepted")
	}
	other := q
	makeSelfSigned(&other)
	got.Domain = q.Domain
	got.Key = other.Key
	if _, e = validateCertificate(got); e == nil {
		t.Fatal("mismatching key accepted")
	}
}

func TestCertificatePolicyIsIndependentCASAndRenewalPreservesPolicy(t *testing.T) {
	s, _, _ := testServer(t)
	ctx := context.Background()
	payload, _ := json.Marshal(CertificateRequest{Name: "Synthetic TLS", Domain: "transport.example.com", Method: "self-signed", Days: 3})
	id, _ := s.newJob(ctx, "policy_cert_issue", "certificate", "policy_cert", "Issue", JobPayload{Kind: "issue", Certificate: "policy_cert", Payload: payload})
	s.processJob(ctx, id)
	original, rev, _ := s.readCertificate(ctx, "policy_cert")
	update := func(input string) int {
		req := httptest.NewRequest("PUT", "/api/certificates/policy_cert/policy", strings.NewReader(input))
		req.SetPathValue("id", "policy_cert")
		rec := httptest.NewRecorder()
		s.certificatePolicy(rec, req)
		return rec.Code
	}
	if update(`{"expected_policy_revision":0,"auto_deploy":true,"confirm":true}`) != 200 {
		t.Fatal("policy update failed")
	}
	if update(`{"expected_policy_revision":0,"auto_deploy":false,"confirm":true}`) == 200 {
		t.Fatal("concurrent policy silently overwritten")
	}
	q, current, _ := s.readCertificate(ctx, "policy_cert")
	if !q.AutoDeploy || current != rev || q.Key != original.Key {
		t.Fatal("policy changed issued revision or key")
	}
	q.AutoDeploy = false
	payload, _ = json.Marshal(q)
	job, _ := s.newJob(ctx, "policy_cert_renew", "certificate", "policy_cert", "Renew", JobPayload{Kind: "issue", Certificate: "policy_cert", ExpectedRevision: rev, Payload: payload})
	s.processJob(ctx, job)
	renewed, current, e := s.readCertificate(ctx, "policy_cert")
	if e != nil || current != rev+1 || !renewed.AutoDeploy || renewed.Cert == original.Cert {
		t.Fatal("renewal changed policy/password or did not issue new certificate")
	}
}
