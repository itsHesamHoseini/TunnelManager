package nodeops

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/itsHesamHoseini/TunnelManager/internal/config"
	"github.com/itsHesamHoseini/TunnelManager/internal/engine"
	"github.com/itsHesamHoseini/TunnelManager/internal/protocol"
)

type Runtime struct {
	ConfigDir, StateDir string
	mu                  sync.Mutex
}

func New(c config.Config) *Runtime {
	return &Runtime{ConfigDir: c.ConfigDir, StateDir: "/var/lib/tunnelmanager-agent"}
}

type Instance struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Engine         string   `json:"engine"`
	Version        string   `json:"version"`
	Role           string   `json:"role"`
	Unit           string   `json:"unit"`
	Path           string   `json:"path"`
	Binary         string   `json:"binary"`
	Hash           string   `json:"hash"`
	Managed        bool     `json:"managed"`
	Adopted        bool     `json:"adopted"`
	Stopped        bool     `json:"stopped"`
	Disabled       bool     `json:"disabled"`
	Routes         []string `json:"routes"`
	UnitPath       string   `json:"unit_path,omitempty"`
	UnitHash       string   `json:"unit_hash,omitempty"`
	DefinitionHash string   `json:"definition_hash,omitempty"`
	Epoch          string   `json:"epoch,omitempty"`
}
type Receipt struct {
	Hash    string           `json:"hash"`
	Started bool             `json:"started"`
	Result  *protocol.Result `json:"result,omitempty"`
}

func (r *Runtime) file(parts ...string) string {
	return filepath.Join(append([]string{r.StateDir}, parts...)...)
}
func (r *Runtime) Execute(ctx context.Context, c protocol.Command) protocol.Result {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := protocol.Result{ID: c.ID}
	unlock, lockErr := mutationLock(ctx, r.file("mutation.lock"))
	if lockErr != nil {
		out.Code = "node_operation_lock_unavailable"
		return out
	}
	defer unlock()
	if !engine.ID(c.ID) || c.Expires.Before(time.Now()) || c.Expires.After(time.Now().Add(20*time.Minute)) {
		out.Code = "expired_or_invalid_command"
		return out
	}
	hash := engine.Digest(append([]byte(c.Kind+"\n"), c.Payload...))
	path := r.file("receipts", c.ID+".json")
	var receipt Receipt
	if b, e := os.ReadFile(path); e == nil {
		if json.Unmarshal(b, &receipt) != nil || receipt.Hash != hash {
			out.Code = "command_identity_conflict"
			return out
		}
		if receipt.Result != nil {
			return *receipt.Result
		}
		if receipt.Started && c.Kind != "certificate.deploy" {
			out.Code = "interrupted_action_requires_review"
			return out
		}
	}
	receipt = Receipt{Hash: hash, Started: true}
	if e := writeJSON(path, receipt); e != nil {
		out.Code = "receipt_unavailable"
		return out
	}
	ctx, cancel := context.WithTimeout(ctx, 50*time.Second)
	defer cancel()
	data, e := r.dispatch(ctx, c.Kind, c.Payload)
	if e != nil {
		out.Code = e.Error()
	} else {
		out.OK = true
		out.Data, _ = json.Marshal(data)
	}
	if len(out.Data) > 180*1024 {
		out.OK = false
		out.Code = "result_limit_exceeded"
		out.Data = nil
	}
	receipt.Result = &out
	writeJSON(path, receipt)
	return out
}
func decode(b []byte, v any) error {
	if len(b) > 192*1024 {
		return errors.New("payload_limit_exceeded")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return errors.New("invalid_typed_payload")
	}
	var trailing any
	if d.Decode(&trailing) != io.EOF {
		return errors.New("invalid_typed_payload")
	}
	return nil
}
func writeJSON(p string, v any) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	return config.Atomic(p, b, 0600)
}
func (r *Runtime) load(id string) (Instance, error) {
	if !engine.ID(id) {
		return Instance{}, errors.New("invalid_instance_id")
	}
	b, e := os.ReadFile(r.file("instances", id+".json"))
	var v Instance
	if e != nil || json.Unmarshal(b, &v) != nil || !v.Managed || v.ID != id {
		return v, errors.New("instance_not_adopted")
	}
	return v, nil
}
func (r *Runtime) save(v Instance) error { return writeJSON(r.file("instances", v.ID+".json"), v) }
func run(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var out boundBuffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if e := cmd.Run(); e != nil {
		return nil, errors.New("native_command_failed")
	}
	return out.Bytes(), nil
}

type boundBuffer struct{ bytes.Buffer }

func (b *boundBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 1024*1024 {
		return 0, errors.New("output_bound_exceeded")
	}
	return b.Buffer.Write(p)
}
func native() error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("native_linux_root_required")
	}
	return nil
}
func (r *Runtime) dispatch(ctx context.Context, kind string, b json.RawMessage) (any, error) {
	switch kind {
	case "inventory":
		var q struct{ MatchKey string }
		if e := decode(b, &q); e != nil {
			return nil, e
		}
		key, _ := base64.RawURLEncoding.DecodeString(q.MatchKey)
		return r.Inventory(ctx, key)
	case "engine.install":
		var q struct{ Engine, Version string }
		if e := decode(b, &q); e != nil {
			return nil, e
		}
		return r.install(ctx, q.Engine, q.Version)
	case "instance.adopt":
		return r.adopt(ctx, b)
	case "change.preflight":
		return r.preflight(ctx, b)
	case "change.prepare":
		return r.prepare(ctx, b)
	case "change.activate":
		return r.activate(ctx, b)
	case "change.confirm":
		return r.confirm(ctx, b)
	case "change.rollback":
		var q struct {
			ID         string
			Compensate bool
		}
		if e := decode(b, &q); e != nil {
			return nil, e
		}
		return nil, r.revert(ctx, q.ID, q.Compensate)
	case "instance.action":
		return r.action(ctx, b)
	case "instance.config":
		var q struct{ ID string }
		if e := decode(b, &q); e != nil {
			return nil, e
		}
		v, e := r.resolve(ctx, q.ID)
		if e != nil {
			return nil, e
		}
		raw, e := os.ReadFile(v.Path)
		if e != nil {
			return nil, errors.New("config_unreadable")
		}
		return map[string]any{"configuration": engine.Redact(string(raw)), "hash": engine.Digest(raw), "drift": v.Hash != engine.Digest(raw)}, nil
	case "logs.read":
		return r.logs(ctx, b)
	case "instance.status":
		return r.status(ctx, b)
	case "tools.status":
		return r.tools(ctx, b)
	case "diagnostic":
		return r.diagnostic(ctx, b)
	case "certificate.deploy":
		return r.deployCertificate(ctx, b)
	case "recovery.policy":
		return r.recoveryPolicy(ctx, b)
	default:
		return nil, errors.New("unknown_typed_action")
	}
}
func (r *Runtime) install(ctx context.Context, name, version string) (any, error) {
	if e := native(); e != nil {
		return nil, e
	}
	a, e := engine.ArtifactFor(name, version, runtime.GOARCH)
	if e != nil {
		return nil, errors.New("unsupported_engine_version")
	}
	dest := filepath.Join("/opt/tunnelmanager/engines", name, version, name)
	if b, e := os.ReadFile(dest + ".artifact.json"); e == nil {
		var old struct {
			Artifact   engine.Artifact
			BinaryHash string
		}
		if json.Unmarshal(b, &old) == nil && old.Artifact.SHA256 == a.SHA256 {
			if current, e := readRegular(dest, 64*1024*1024); e == nil && old.BinaryHash == engine.Digest(current) {
				return map[string]any{"installed": true, "version": version, "unchanged": true}, nil
			}
		}
	}
	client := http.Client{Timeout: 40 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" || len(via) > 5 {
			return errors.New("download_redirect_rejected")
		}
		return nil
	}}
	req, _ := http.NewRequestWithContext(ctx, "GET", a.URL, nil)
	resp, e := client.Do(req)
	if e != nil {
		return nil, errors.New("engine_download_unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, errors.New("engine_download_rejected")
	}
	archive, e := io.ReadAll(io.LimitReader(resp.Body, 32*1024*1024+1))
	if e != nil || len(archive) > 32*1024*1024 || engine.Digest(archive) != a.SHA256 {
		return nil, errors.New("engine_checksum_mismatch")
	}
	var binary []byte
	if strings.HasSuffix(a.URL, ".zip") {
		z, e := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
		if e != nil {
			return nil, errors.New("invalid_engine_archive")
		}
		for _, f := range z.File {
			if f.Name == a.Entry && !f.FileInfo().IsDir() {
				rd, e := f.Open()
				if e != nil {
					return nil, e
				}
				binary, e = io.ReadAll(io.LimitReader(rd, 64*1024*1024))
				rd.Close()
				if e != nil {
					return nil, e
				}
			}
		}
	} else {
		gz, e := gzip.NewReader(bytes.NewReader(archive))
		if e != nil {
			return nil, errors.New("invalid_engine_archive")
		}
		defer gz.Close()
		tr := tar.NewReader(gz)
		for {
			h, e := tr.Next()
			if e == io.EOF {
				break
			}
			if e != nil {
				return nil, errors.New("invalid_engine_archive")
			}
			if strings.TrimPrefix(h.Name, "./") == a.Entry && h.Typeflag == tar.TypeReg {
				binary, e = io.ReadAll(io.LimitReader(tr, 64*1024*1024))
				if e != nil {
					return nil, e
				}
				break
			}
		}
	}
	if len(binary) < 4 || string(binary[:4]) != "\x7fELF" {
		return nil, errors.New("engine_archive_has_no_binary")
	}
	if e = config.Atomic(dest, binary, 0755); e != nil {
		return nil, e
	}
	if e = writeJSON(dest+".artifact.json", map[string]any{"Artifact": a, "BinaryHash": engine.Digest(binary)}); e != nil {
		return nil, e
	}
	return map[string]any{"installed": true, "engine": name, "version": version, "license": a.License}, nil
}
