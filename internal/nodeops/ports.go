package nodeops

import (
	"context"
	"errors"
	"github.com/itsHesamHoseini/TunnelManager/internal/engine"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var publishedPort = regexp.MustCompile(`(\[[0-9a-fA-F:]+\]|[0-9a-fA-F:.]+):(\d+)(?:-(\d+))?->\d+(?:-\d+)?/(tcp|udp)`)

func dockerConflict(output string, bind engine.Binding) bool {
	for _, m := range publishedPort.FindAllStringSubmatch(output, 1000) {
		if m[4] != bind.Protocol {
			continue
		}
		low, _ := strconv.Atoi(m[2])
		high := low
		if m[3] != "" {
			high, _ = strconv.Atoi(m[3])
		}
		if bind.Port < low || bind.Port > high {
			continue
		}
		host := strings.Trim(m[1], "[]")
		if engine.Conflict(bind, engine.Binding{Host: host, Port: bind.Port, Protocol: m[4]}) {
			return true
		}
	}
	return false
}
func dockerPorts(ctx context.Context) (string, error) {
	if _, e := os.Stat("/var/run/docker.sock"); os.IsNotExist(e) {
		return "", nil
	}
	out, e := run(ctx, "docker", "ps", "--format", "{{.Ports}}")
	if e != nil {
		return "", errors.New("docker_port_reservations_unavailable")
	}
	return string(out), nil
}
