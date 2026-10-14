package config

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
)

type Config struct {
	Mode       string `json:"mode"`
	Domain     string `json:"domain"`
	Port       int    `json:"port"`
	Dir        string `json:"dir"`
	ConfigDir  string `json:"config_dir"`
	Language   string `json:"language"`
	TLS        string `json:"tls"`
	Cert       string `json:"cert,omitempty"`
	Key        string `json:"key,omitempty"`
	Controller string `json:"controller,omitempty"`
	NodeID     string `json:"node_id,omitempty"`
	Identity   string `json:"identity,omitempty"`
	CA         string `json:"ca,omitempty"`
	Database   string `json:"database,omitempty"`
	Bind       string `json:"bind,omitempty"`
	Profile    string `json:"profile"`
	Admin      string `json:"admin,omitempty"`
}

func Default() Config {
	return Config{Mode: "controller", Domain: "", Port: 9443, Dir: "/opt/tunnelmanager", ConfigDir: "/etc/tunnelmanager", Language: "en", TLS: "self-signed", Database: "db", Profile: "standard", Admin: "admin", Bind: "0.0.0.0"}
}
func Load(path string) (Config, error) {
	b, e := os.ReadFile(path)
	c := Default()
	if e != nil {
		return c, e
	}
	e = json.Unmarshal(b, &c)
	return c, e
}
func Write(path string, c Config) error {
	b, e := json.MarshalIndent(c, "", "  ")
	if e != nil {
		return e
	}
	return Atomic(path, b, 0600)
}
func Atomic(path string, b []byte, mode os.FileMode) error {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	tmp, e := os.CreateTemp(filepath.Dir(path), ".tm-")
	if e != nil {
		return e
	}
	defer os.Remove(tmp.Name())
	if e = tmp.Chmod(mode); e != nil {
		tmp.Close()
		return e
	}
	if _, e = tmp.Write(b); e == nil {
		e = tmp.Sync()
	}
	if ce := tmp.Close(); e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	return os.Rename(tmp.Name(), path)
}
func (c Config) Origin() string {
	if c.Port == 443 {
		return "https://" + c.Domain
	}
	return fmt.Sprintf("https://%s:%d", c.Domain, c.Port)
}
func (c Config) DatabaseURL() (string, error) {
	b, e := os.ReadFile(filepath.Join(c.ConfigDir, "db-password"))
	if e != nil {
		return "", e
	}
	u := url.URL{Scheme: "postgres", User: url.UserPassword("tunnelmanager", string(b)), Host: c.Database + ":5432", Path: "/tunnelmanager", RawQuery: "sslmode=disable"}
	return u.String(), nil
}
