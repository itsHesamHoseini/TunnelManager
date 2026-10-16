package controller

import (
	"bytes"
	"context"
	"encoding/json"
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
	if e != nil || rev != 1 || got.Key == "" || got.PKCS12Password == "" {
		t.Fatal("protected certificate absent")
	}
	leaf, e := validateCertificate(got)
	if e != nil || leaf.VerifyHostname(q.Domain) != nil {
		t.Fatal("certificate invalid")
	}
	var cipher []byte
	s.DB.QueryRow(ctx, "SELECT cipher FROM certificates WHERE id='cert1'").Scan(&cipher)
	if bytes.Contains(cipher, []byte(got.Key)) || bytes.Contains(cipher, []byte(got.PKCS12Password)) {
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
