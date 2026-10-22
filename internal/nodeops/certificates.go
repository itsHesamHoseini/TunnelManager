package nodeops

import "time"

type Certificate struct {
	Stage        string    `json:"stage"`
	Deadline     time.Time `json:"deadline"`
	RequestID    string    `json:"request_id"`
	ID           string    `json:"id"`
	Domain       string    `json:"domain"`
	Cert         string    `json:"cert"`
	Key          string    `json:"key,omitempty"`
	ExpectedHash string    `json:"expected_hash"`
	Instances    []string  `json:"instances"`
	TrustOnly    bool      `json:"trust_only"`
	Confirm      bool      `json:"confirm"`
}
