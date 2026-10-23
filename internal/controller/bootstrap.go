package controller

import (
	"crypto/sha256"
	gobuild "debug/buildinfo"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

//go:embed node_bootstrap.sh
var nodeBootstrapScript string

const nodeArtifactLimit = 128 << 20

type nodeArtifact struct {
	Path, Hash, Arch string
	Size             int64
}

func openNodeArtifact(path string) (*os.File, nodeArtifact, error) {
	var meta nodeArtifact
	f, err := os.Open(path)
	if err != nil {
		return nil, meta, err
	}
	good := false
	defer func() {
		if !good {
			f.Close()
		}
	}()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() < 64 || st.Size() > nodeArtifactLimit {
		return nil, meta, errors.New("node_artifact_unavailable")
	}
	header := make([]byte, 64)
	if _, err = io.ReadFull(f, header); err != nil || string(header[:4]) != "\x7fELF" || header[4] != 2 || header[5] != 1 {
		return nil, meta, errors.New("node_artifact_requires_linux")
	}
	switch binary.LittleEndian.Uint16(header[18:20]) {
	case 62:
		meta.Arch = "amd64"
	case 183:
		meta.Arch = "arm64"
	default:
		return nil, meta, errors.New("node_artifact_architecture_unsupported")
	}
	info, err := gobuild.Read(f)
	if err != nil {
		return nil, meta, errors.New("node_artifact_metadata_missing")
	}
	linux, arch := false, ""
	for _, setting := range info.Settings {
		if setting.Key == "GOOS" {
			linux = setting.Value == "linux"
		}
		if setting.Key == "GOARCH" {
			arch = setting.Value
		}
	}
	if !linux || arch != meta.Arch {
		return nil, meta, errors.New("node_artifact_requires_linux")
	}
	if _, err = f.Seek(0, 0); err != nil {
		return nil, meta, err
	}
	digest := sha256.New()
	count, err := io.Copy(digest, io.LimitReader(f, nodeArtifactLimit+1))
	if err != nil || count != st.Size() {
		return nil, meta, errors.New("node_artifact_changed")
	}
	if _, err = f.Seek(0, 0); err != nil {
		return nil, meta, err
	}
	meta.Path = path
	meta.Hash = hex.EncodeToString(digest.Sum(nil))
	meta.Size = count
	good = true
	return f, meta, nil
}
func shellLiteral(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }
func (s *Server) bootstrapArtifact() (*nodeArtifact, error) {
	s.bootstrapOnce.Do(func() {
		path := s.bootstrapPath
		if path == "" {
			if runtime.GOOS == "linux" {
				path = "/proc/self/exe"
			} else {
				path, s.bootstrapError = os.Executable()
			}
		}
		if s.bootstrapError != nil {
			return
		}
		f, meta, err := openNodeArtifact(path)
		if err != nil {
			s.bootstrapError = err
			return
		}
		f.Close()
		s.bootstrapMeta = &meta
	})
	return s.bootstrapMeta, s.bootstrapError
}
func (s *Server) bootstrapOrigin() (string, error) {
	u, err := url.Parse(s.Config.Origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" {
		return "", errors.New("invalid_bootstrap_origin")
	}
	return strings.TrimSuffix(s.Config.Origin, "/"), nil
}
func (s *Server) bootstrapCommand() (string, error) {
	if _, err := s.bootstrapArtifact(); err != nil {
		return "", err
	}
	origin, err := s.bootstrapOrigin()
	if err != nil {
		return "", err
	}
	// No supplied name/token/command becomes shell text. Only the configured
	// HTTPS origin is single-quoted, and private enrollment stays in the prompt.
	return `(umask 077; task_dir="$(mktemp -d /tmp/tm-node-start.XXXXXXXX)" || exit; trap 'case "$task_dir" in /tmp/tm-node-start.*) rm -rf -- "$task_dir";; esac' EXIT HUP INT TERM; curl --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 30 -fsSL ` + shellLiteral(origin+"/bootstrap/node-install.sh") + ` -o "$task_dir/setup.sh" && sh "$task_dir/setup.sh")`, nil
}
func (s *Server) bootstrapScript(w http.ResponseWriter, r *http.Request) {
	if s.limited(w, r, "node-bootstrap:"+s.ip(r), .05, 4) {
		return
	}
	meta, err := s.bootstrapArtifact()
	if err != nil {
		fail(w, 503, "node_artifact_unavailable", "A matching Linux controller artifact is required.", "این ساخت باینری لینوکسیِ قابل نصب ارائه نمی‌کند؛ از فایل تأییدشدهٔ مناسب استفاده کنید.")
		return
	}
	origin, err := s.bootstrapOrigin()
	if err != nil {
		badOperation(w, err)
		return
	}
	script := strings.NewReplacer("@ARCH@", meta.Arch, "@HASH@", meta.Hash, "@ORIGIN@", shellLiteral(origin)).Replace(nodeBootstrapScript)
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	io.WriteString(w, script)
}
func (s *Server) bootstrapDownload(w http.ResponseWriter, r *http.Request) {
	if s.limited(w, r, "node-download:"+s.ip(r), .03, 2) {
		return
	}
	select {
	case s.bootstrapSlots <- struct{}{}:
		defer func() { <-s.bootstrapSlots }()
	default:
		fail(w, 429, "busy", "An artifact download is in progress. Retry shortly.", "دریافت یک فایل در جریان است؛ کمی بعد دوباره تلاش کنید.")
		return
	}
	meta, err := s.bootstrapArtifact()
	if err != nil || r.PathValue("arch") != meta.Arch {
		fail(w, 404, "node_artifact_unavailable", "No matching Linux artifact.", "باینری لینوکسیِ سازگار در این پنل موجود نیست.")
		return
	}
	file, current, err := openNodeArtifact(meta.Path)
	if err != nil {
		fail(w, 503, "node_artifact_changed", "Controller artifact changed. Wait for restart.", "فایل پنل تغییر کرده؛ منتظر پایان به‌روزرسانی بمانید.")
		return
	}
	defer file.Close()
	if current.Hash != meta.Hash || current.Size != meta.Size || current.Arch != meta.Arch {
		fail(w, 503, "node_artifact_changed", "Controller artifact changed. Wait for restart.", "فایل پنل تغییر کرده؛ منتظر پایان به‌روزرسانی بمانید.")
		return
	}
	deadline := http.NewResponseController(w)
	if err := deadline.SetWriteDeadline(time.Now().Add(5 * time.Minute)); err != nil {
		fail(w, 503, "node_artifact_unavailable", "Bounded download unavailable.", "دریافت محدود فایل در دسترس نیست؛ کمی بعد دوباره تلاش کنید.")
		return
	}
	defer deadline.SetWriteDeadline(time.Time{})
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="tunnelmanager-linux-`+meta.Arch+`"`)
	w.Header().Set("Content-Length", strconv.FormatInt(meta.Size, 10))
	w.Header().Set("Cache-Control", "no-store")
	io.Copy(w, file)
}
