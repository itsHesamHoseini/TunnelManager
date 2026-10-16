package controller

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"regexp"
	"time"

	"github.com/itsHesamHoseini/TunnelManager/internal/secure"
)

type CertificateRequest struct {
	Name           string `json:"name"`
	Domain         string `json:"domain"`
	Method         string `json:"method"`
	Cert           string `json:"cert"`
	Key            string `json:"key"`
	Days           int    `json:"days"`
	Email          string `json:"email"`
	Zone           string `json:"zone"`
	ProviderToken  string `json:"provider_token"`
	Staging        bool   `json:"staging"`
	AutoRenew      bool   `json:"auto_renew"`
	AutoDeploy     bool   `json:"auto_deploy"`
	AcceptTerms    bool   `json:"accept_terms"`
	PKCS12Password string `json:"pkcs12_password"`
	AccountKey     string `json:"account_key"`
	OrderURL       string `json:"order_url"`
	RecordID       string `json:"record_id"`
}
type CertificateDeployment struct {
	Node      string   `json:"node"`
	Instances []string `json:"instances"`
	TrustOnly bool     `json:"trust_only"`
}

var domainRE = regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$`)

func validateCertificate(q CertificateRequest) (*x509.Certificate, error) {
	pair, e := tls.X509KeyPair([]byte(q.Cert), []byte(q.Key))
	if e != nil {
		return nil, errors.New("certificate_key_mismatch")
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil || leaf.VerifyHostname(q.Domain) != nil || leaf.NotBefore.After(time.Now().Add(5*time.Minute)) || time.Until(leaf.NotAfter) < time.Hour {
		return nil, errors.New("certificate_name_time_or_expiry_invalid")
	}
	return leaf, nil
}
func makeSelfSigned(q *CertificateRequest) error {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return e
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	days := q.Days
	if days < 1 || days > 397 {
		days = 90
	}
	leaf := x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: q.Domain}, NotBefore: time.Now().Add(-5 * time.Minute), NotAfter: time.Now().Add(time.Duration(days) * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	if ip := net.ParseIP(q.Domain); ip != nil {
		leaf.IPAddresses = []net.IP{ip}
	} else {
		leaf.DNSNames = []string{q.Domain}
	}
	der, e := x509.CreateCertificate(rand.Reader, &leaf, &leaf, &key.PublicKey, key)
	if e != nil {
		return e
	}
	private, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return e
	}
	q.Cert = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	q.Key = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
	return nil
}
func (s *Server) certificateList(w http.ResponseWriter, r *http.Request) {
	rows, e := s.DB.Query(r.Context(), "SELECT id,name,domain,revision,not_after,issuer,method,metadata FROM certificates ORDER BY name")
	if e != nil {
		badOperation(w, e)
		return
	}
	items := []map[string]any{}
	for rows.Next() {
		var id, name, domain, issuer, method string
		var rev int64
		var until time.Time
		var meta []byte
		rows.Scan(&id, &name, &domain, &rev, &until, &issuer, &method, &meta)
		items = append(items, map[string]any{"id": id, "name": name, "domain": domain, "revision": rev, "not_after": until, "issuer": issuer, "method": method, "metadata": json.RawMessage(meta)})
	}
	rows.Close()
	for i := range items {
		rows, e := s.DB.Query(r.Context(), "SELECT l.node_id,n.name,l.instance_id,l.trust_only,l.hash,l.revision FROM certificate_links l JOIN nodes n ON n.id=l.node_id WHERE certificate_id=$1", items[i]["id"])
		links := []any{}
		if e == nil {
			for rows.Next() {
				var node, name, instance, hash string
				var trust bool
				var deployedRevision int64
				rows.Scan(&node, &name, &instance, &trust, &hash, &deployedRevision)
				links = append(links, map[string]any{"node": node, "name": name, "instance": instance, "trust_only": trust, "hash": hash, "deployed_revision": deployedRevision})
			}
			rows.Close()
		}
		items[i]["links"] = links
	}
	write(w, items)
}
func (s *Server) certificateRequest(w http.ResponseWriter, r *http.Request) {
	var q struct {
		RequestKey       string             `json:"request_key"`
		ID               string             `json:"id"`
		ExpectedRevision int64              `json:"expected_revision"`
		Confirm          bool               `json:"confirm"`
		Request          CertificateRequest `json:"request"`
	}
	if !decode(w, r, &q) {
		return
	}
	input, _ := json.Marshal(q)
	requestHash := secure.Hash(string(s.Config.Key) + "certificate:" + string(input))
	var priorID, priorTarget, priorHash string
	if s.DB.QueryRow(r.Context(), "SELECT id,target,request_hash FROM operations WHERE request_key=$1", q.RequestKey).Scan(&priorID, &priorTarget, &priorHash) == nil {
		if requestHash != priorHash {
			badOperation(w, errors.New("request_key_reused_with_different_input"))
			return
		}
		write(w, map[string]string{"operation_id": priorID, "certificate_id": priorTarget})
		return
	}
	if !q.Confirm || q.Request.Name == "" || len(q.Request.Name) > 100 || (!domainRE.MatchString(q.Request.Domain) && net.ParseIP(q.Request.Domain) == nil) {
		badOperation(w, errors.New("review_certificate_domain_and_confirm"))
		return
	}
	if q.Request.Method != "upload" && q.Request.Method != "self-signed" && q.Request.Method != "acme" {
		badOperation(w, errors.New("select_certificate_method"))
		return
	}
	if q.ID == "" {
		q.ID = secure.Token(15)
	} else {
		old, rev, e := s.readCertificate(r.Context(), q.ID)
		if e != nil || rev != q.ExpectedRevision {
			badOperation(w, errors.New("certificate_revision_changed"))
			return
		}
		if q.Request.ProviderToken == "" {
			q.Request.ProviderToken = old.ProviderToken
		}
		q.Request.AccountKey = old.AccountKey
		q.Request.PKCS12Password = old.PKCS12Password
		if q.Request.Domain != old.Domain {
			var linked bool
			s.DB.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM certificate_links WHERE certificate_id=$1 AND instance_id<>'')", q.ID).Scan(&linked)
			if linked {
				badOperation(w, errors.New("create_a_separate_certificate_for_a_linked_hostname_change"))
				return
			}
		}
	}
	if q.Request.Method != "acme" {
		q.Request.Staging = false
	}
	if q.Request.Method == "upload" {
		if _, e := validateCertificate(q.Request); e != nil {
			badOperation(w, e)
			return
		}
	}
	b, _ := json.Marshal(q.Request)
	op, e := s.newJob(r.Context(), q.RequestKey, "certificate", q.ID, q.Request.Name, JobPayload{RequestHash: requestHash, Kind: "issue", Certificate: q.ID, ExpectedRevision: q.ExpectedRevision, Payload: b})
	if e != nil {
		badOperation(w, e)
		return
	}
	write(w, map[string]string{"operation_id": op, "certificate_id": q.ID})
}
func (s *Server) readCertificate(ctx context.Context, id string) (CertificateRequest, int64, error) {
	var cipher []byte
	var rev int64
	var q CertificateRequest
	var meta []byte
	if e := s.DB.QueryRow(ctx, "SELECT cipher,revision,metadata FROM certificates WHERE id=$1", id).Scan(&cipher, &rev, &meta); e != nil {
		return q, 0, errors.New("certificate_missing")
	}
	if e := s.openValue("certificate:"+id, cipher, &q); e != nil {
		return q, rev, e
	}
	var policy struct {
		AutoRenew  bool `json:"auto_renew"`
		AutoDeploy bool `json:"auto_deploy"`
	}
	json.Unmarshal(meta, &policy)
	q.AutoRenew = policy.AutoRenew
	q.AutoDeploy = policy.AutoDeploy
	return q, rev, nil
}
func (s *Server) certificateDeploy(w http.ResponseWriter, r *http.Request) {
	var q struct {
		RequestKey       string                  `json:"request_key"`
		ExpectedRevision int64                   `json:"expected_revision"`
		Confirm          bool                    `json:"confirm"`
		Deployments      []CertificateDeployment `json:"deployments"`
	}
	if !decode(w, r, &q) {
		return
	}
	_, rev, e := s.readCertificate(r.Context(), r.PathValue("id"))
	if e != nil || rev != q.ExpectedRevision || !q.Confirm || len(q.Deployments) < 1 || len(q.Deployments) > 20 {
		badOperation(w, errors.New("review_certificate_deployment_targets"))
		return
	}
	selected := map[string]bool{}
	for _, target := range q.Deployments {
		if selected[target.Node] {
			badOperation(w, errors.New("duplicate_certificate_target"))
			return
		}
		selected[target.Node] = true
	}
	rows, e := s.DB.Query(r.Context(), "SELECT DISTINCT node_id FROM certificate_links WHERE certificate_id=$1 AND revision<$2", r.PathValue("id"), rev)
	if e != nil {
		badOperation(w, e)
		return
	}
	missing := false
	for rows.Next() {
		var node string
		rows.Scan(&node)
		if !selected[node] {
			missing = true
		}
	}
	rows.Close()
	if missing {
		badOperation(w, errors.New("renewal_requires_all_linked_nodes"))
		return
	}
	b, _ := json.Marshal(q.Deployments)
	op, e := s.newJob(r.Context(), q.RequestKey, "certificate", r.PathValue("id"), "Deploy certificate", JobPayload{Kind: "deploy", Certificate: r.PathValue("id"), ExpectedRevision: rev, Payload: b})
	if e != nil {
		badOperation(w, e)
		return
	}
	write(w, map[string]string{"operation_id": op})
}
func (s *Server) processCertificate(ctx context.Context, id string, q JobPayload) {
	s.phase(ctx, id, "running", nil, nil)
	fail := func(e error) { s.phase(ctx, id, "failed", nil, e) }
	if q.Kind == "issue" {
		var req CertificateRequest
		if json.Unmarshal(q.Payload, &req) != nil {
			fail(errors.New("invalid_certificate_request"))
			return
		}
		if q.ExpectedRevision > 0 {
			old, rev, e := s.readCertificate(ctx, q.Certificate)
			if e != nil || rev != q.ExpectedRevision {
				fail(errors.New("certificate_revision_changed"))
				return
			}
			req.PKCS12Password = old.PKCS12Password
			if req.ProviderToken == "" {
				req.ProviderToken = old.ProviderToken
			}
			if req.AccountKey == "" {
				req.AccountKey = old.AccountKey
			}
		}
		if req.PKCS12Password == "" {
			req.PKCS12Password = secure.Token(24)
		}
		if req.Method == "self-signed" {
			if e := makeSelfSigned(&req); e != nil {
				fail(e)
				return
			}
		}
		if req.Method == "acme" {
			save := func() error {
				q.Payload, _ = json.Marshal(req)
				cipher, e := s.sealValue("operation:"+id, q)
				if e != nil {
					return e
				}
				_, e = s.DB.Exec(ctx, "UPDATE operations SET cipher=$1 WHERE id=$2", cipher, id)
				return e
			}
			if e := s.issueACME(ctx, id, &req, save); e != nil {
				fail(e)
				return
			}
		}
		leaf, e := validateCertificate(req)
		if e != nil {
			fail(e)
			return
		}
		req.OrderURL = ""
		req.RecordID = ""
		cipher, e := s.sealValue("certificate:"+q.Certificate, req)
		if e != nil {
			fail(e)
			return
		}
		meta, _ := json.Marshal(map[string]any{"auto_renew": req.AutoRenew, "auto_deploy": req.AutoDeploy, "email": req.Email, "zone": req.Zone, "staging": req.Method == "acme" && req.Staging, "trust": map[bool]string{true: "self-signed; deploy explicit trust to clients", false: "verify issuer chain at the destination"}[req.Method == "self-signed"]})
		if q.ExpectedRevision == 0 {
			_, e = s.DB.Exec(ctx, "INSERT INTO certificates(id,name,domain,cipher,not_after,issuer,method,metadata)VALUES($1,$2,$3,$4,$5,$6,$7,$8)", q.Certificate, req.Name, req.Domain, cipher, leaf.NotAfter, leaf.Issuer.String(), req.Method, meta)
		} else {
			tag, err := s.DB.Exec(ctx, "UPDATE certificates SET cipher=$1,revision=revision+1,not_after=$2,issuer=$3,metadata=$4::jsonb || jsonb_build_object('auto_renew',CASE WHEN $9='acme' THEN metadata->'auto_renew' ELSE 'false'::jsonb END,'auto_deploy',metadata->'auto_deploy','policy_revision',COALESCE(metadata->'policy_revision','0'::jsonb)),name=$7,domain=$8,method=$9,updated=now() WHERE id=$5 AND revision=$6", cipher, leaf.NotAfter, leaf.Issuer.String(), meta, q.Certificate, q.ExpectedRevision, req.Name, req.Domain, req.Method)
			e = err
			if e == nil && tag.RowsAffected() != 1 {
				e = errors.New("certificate_revision_changed")
			}
		}
		if e != nil {
			fail(e)
			return
		}
		s.phase(ctx, id, "succeeded", map[string]any{"certificate_id": q.Certificate, "not_after": leaf.NotAfter, "private_material": "encrypted"}, nil)
		latest, _, _ := s.readCertificate(ctx, q.Certificate)
		if latest.AutoDeploy {
			s.queueCertificateDeployment(ctx, q.Certificate, q.ExpectedRevision+1, req.Name)
		}
		return
	}
	s.deployCertificateTransaction(ctx, id, q)
}

func (s *Server) scheduleRenewals(ctx context.Context) {
	rows, e := s.DB.Query(ctx, `SELECT id,revision,cipher FROM certificates c WHERE method='acme' AND not_after<now()+interval '30 days' AND metadata->>'auto_renew'='true' AND NOT EXISTS(SELECT 1 FROM operations o WHERE o.target=c.id AND o.kind='certificate' AND o.created>now()-interval '1 day') LIMIT 2`)
	if e != nil {
		return
	}
	type value struct {
		id     string
		rev    int64
		cipher []byte
	}
	values := []value{}
	for rows.Next() {
		var v value
		rows.Scan(&v.id, &v.rev, &v.cipher)
		values = append(values, v)
	}
	rows.Close()
	for _, v := range values {
		req, _, e := s.readCertificate(ctx, v.id)
		if e != nil {
			continue
		}
		b, _ := json.Marshal(req)
		s.newJob(ctx, "renew_"+v.id+"_"+time.Now().UTC().Format("20060102"), "certificate", v.id, req.Name, JobPayload{Kind: "issue", Certificate: v.id, ExpectedRevision: v.rev, Payload: b})
	}
}

func (s *Server) certificatePolicy(w http.ResponseWriter, r *http.Request) {
	var q struct {
		ExpectedRevision int64 `json:"expected_policy_revision"`
		AutoRenew        bool  `json:"auto_renew"`
		AutoDeploy       bool  `json:"auto_deploy"`
		Confirm          bool  `json:"confirm"`
	}
	if !decode(w, r, &q) {
		return
	}
	req, _, e := s.readCertificate(r.Context(), r.PathValue("id"))
	if e != nil || !q.Confirm {
		badOperation(w, errors.New("review_certificate_policy"))
		return
	}
	if q.AutoRenew && req.Method != "acme" {
		badOperation(w, errors.New("automatic_renewal_requires_acme"))
		return
	}
	tag, e := s.DB.Exec(r.Context(), `UPDATE certificates SET metadata=metadata||jsonb_build_object('auto_renew',$1::bool,'auto_deploy',$2::bool,'policy_revision',$3::bigint+1),updated=now() WHERE id=$4 AND COALESCE((metadata->>'policy_revision')::bigint,0)=$3`, q.AutoRenew, q.AutoDeploy, q.ExpectedRevision, r.PathValue("id"))
	if e != nil || tag.RowsAffected() != 1 {
		badOperation(w, errors.New("certificate_policy_changed_refresh"))
		return
	}
	s.Audit(r.Context(), "certificate-policy", req.Name, "updated")
	write(w, map[string]any{"saved": true, "policy_revision": q.ExpectedRevision + 1})
}
