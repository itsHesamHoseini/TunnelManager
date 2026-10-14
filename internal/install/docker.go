package install

import (
	"context"
	"errors"
	"github.com/itsHesamHoseini/TunnelManager/internal/config"
	"os"
	"regexp"
	"strings"
)

func (i *Installer) InstallDocker(ctx context.Context) error {
	b, e := os.ReadFile("/etc/os-release")
	if e != nil {
		return e
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok {
			values[k] = strings.Trim(v, "\"")
		}
	}
	distro := values["ID"]
	if distro != "ubuntu" && distro != "debian" {
		return errors.New("automatic Docker installation supports Ubuntu/Debian only")
	}
	codename := values["VERSION_CODENAME"]
	if !regexp.MustCompile("^[a-z]+$").MatchString(codename) {
		return errors.New("OS codename invalid")
	}
	if _, e = i.Run(ctx, "apt-get", []string{"update"}, nil); e != nil {
		return e
	}
	if _, e = i.Run(ctx, "apt-get", []string{"install", "-y", "ca-certificates", "curl", "gnupg"}, nil); e != nil {
		return e
	}
	key, e := Fetch(ctx, "https://download.docker.com/linux/"+distro+"/gpg", 65536)
	if e != nil {
		return e
	}
	path := "/etc/apt/keyrings/tunnelmanager-docker.asc"
	if e = config.Atomic(path, key, 0644); e != nil {
		return e
	}
	fingerprint, e := i.Run(ctx, "gpg", []string{"--show-keys", "--with-colons", path}, nil)
	if e != nil || !strings.Contains(string(fingerprint), "9DC858229FC7DD38854AE2D88D81803C0EBFCD88") {
		return errors.New("Docker signing key fingerprint not trusted")
	}
	arch, e := i.Run(ctx, "dpkg", []string{"--print-architecture"}, nil)
	if e != nil {
		return e
	}
	architecture := strings.TrimSpace(string(arch))
	if architecture != "amd64" && architecture != "arm64" {
		return errors.New("Docker architecture unsupported")
	}
	sources := "Types: deb\nURIs: https://download.docker.com/linux/" + distro + "\nSuites: " + codename + "\nComponents: stable\nArchitectures: " + architecture + "\nSigned-By: " + path + "\n"
	if e = config.Atomic("/etc/apt/sources.list.d/tunnelmanager-docker.sources", []byte(sources), 0644); e != nil {
		return e
	}
	if _, e = i.Run(ctx, "apt-get", []string{"update"}, nil); e != nil {
		return e
	}
	if _, e = i.Run(ctx, "apt-get", []string{"install", "-y", "docker-ce", "docker-ce-cli", "containerd.io", "docker-buildx-plugin", "docker-compose-plugin"}, nil); e != nil {
		return e
	}
	_, e = i.Run(ctx, "systemctl", []string{"enable", "--now", "docker"}, nil)
	return e
}
