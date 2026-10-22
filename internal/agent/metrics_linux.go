//go:build linux

package agent

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"github.com/itsHesamHoseini/TunnelManager/internal/protocol"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type processSample struct{ Ticks, Start uint64 }
type Sampler struct {
	at          time.Time
	total, idle uint64
	process     map[int]processSample
	network     map[string][2]uint64
	hz          float64
}

func NewSampler() *Sampler {
	s := &Sampler{process: map[int]processSample{}, network: map[string][2]uint64{}, hz: 100}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if b, e := command(ctx, "getconf", "CLK_TCK"); e == nil {
		if n, e := strconv.ParseFloat(strings.TrimSpace(string(b)), 64); e == nil && n > 0 {
			s.hz = n
		}
	}
	return s
}
func command(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var b limitedBuffer
	cmd.Stdout = &b
	cmd.Stderr = &b
	e := cmd.Run()
	return b.Bytes(), e
}

type limitedBuffer struct{ bytes.Buffer }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 1024*1024 {
		return 0, fmt.Errorf("bounded collection exceeded")
	}
	return b.Buffer.Write(p)
}
func number(s string) uint64 { n, _ := strconv.ParseUint(s, 10, 64); return n }
func (s *Sampler) Collect(parent context.Context) protocol.Telemetry {
	ctx, cancel := context.WithTimeout(parent, 8*time.Second)
	defer cancel()
	now := time.Now()
	delta := now.Sub(s.at).Seconds()
	d := protocol.Telemetry{At: now, Processes: []protocol.Process{}, Networks: []protocol.Network{}, Listeners: []protocol.Listener{}, Services: []protocol.Service{}, Errors: []string{}, Scope: "host; interface bytes are not route traffic; process CPU uses one-core percent"}
	if boot, e := os.ReadFile("/proc/sys/kernel/random/boot_id"); e == nil {
		d.Boot = strings.TrimSpace(string(boot))
	}
	primary := ""
	if routes, e := os.ReadFile("/proc/net/route"); e == nil {
		for _, line := range strings.Split(string(routes), "\n") {
			f := strings.Fields(line)
			if len(f) > 1 && f[1] == "00000000" {
				primary = f[0]
				break
			}
		}
	}
	if b, e := os.ReadFile("/etc/os-release"); e == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				d.OS = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
			}
		}
	}
	if b, e := os.ReadFile("/proc/stat"); e == nil {
		line := strings.SplitN(string(b), "\n", 2)[0]
		fields := strings.Fields(line)
		if len(fields) >= 9 {
			total := uint64(0)
			for _, v := range fields[1:9] {
				total += number(v)
			}
			idle := number(fields[4]) + number(fields[5])
			if !s.at.IsZero() && total > s.total && idle >= s.idle {
				value := 100 * (1 - float64(idle-s.idle)/float64(total-s.total))
				if value >= 0 && value <= 100 {
					d.CPU = &value
				}
			}
			s.total = total
			s.idle = idle
		}
	}
	if b, e := os.ReadFile("/proc/meminfo"); e == nil {
		m := map[string]uint64{}
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				m[strings.TrimSuffix(f[0], ":")] = number(f[1]) * 1024
			}
		}
		d.RAMTotal = m["MemTotal"]
		if m["MemAvailable"] <= d.RAMTotal {
			d.RAMUsed = d.RAMTotal - m["MemAvailable"]
		}
	}
	var fs unix.Statfs_t
	if unix.Statfs("/", &fs) == nil {
		d.DiskTotal = fs.Blocks * uint64(fs.Bsize)
		d.DiskFree = fs.Bavail * uint64(fs.Bsize)
	}
	if b, e := os.ReadFile("/proc/net/dev"); e == nil {
		for _, line := range strings.Split(string(b), "\n") {
			name, v, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			name = strings.TrimSpace(name)
			fields := strings.Fields(v)
			if len(fields) < 16 {
				continue
			}
			rx, tx := number(fields[0]), number(fields[8])
			n := protocol.Network{Name: name, RX: rx, TX: tx, Primary: name == primary}
			if old, ok := s.network[name]; ok && delta > 0 && delta <= 120 && rx >= old[0] && tx >= old[1] {
				r, t := float64(rx-old[0])/delta, float64(tx-old[1])/delta
				n.RXRate = &r
				n.TXRate = &t
			}
			s.network[name] = [2]uint64{rx, tx}
			d.Networks = append(d.Networks, n)
			if len(d.Networks) >= 100 {
				d.Errors = append(d.Errors, "Interface list limited to 100 observations.")
				break
			}
		}
	}
	uptime := 0.0
	if b, e := os.ReadFile("/proc/uptime"); e == nil {
		fmt.Sscan(string(b), &uptime)
	}
	entries, _ := os.ReadDir("/proc")
	next := map[int]processSample{}
	for _, entry := range entries {
		pid, e := strconv.Atoi(entry.Name())
		if e != nil {
			continue
		}
		b, e := os.ReadFile(filepath.Join("/proc", entry.Name(), "stat"))
		if e != nil {
			continue
		}
		end := strings.LastIndex(string(b), ")")
		start := strings.Index(string(b), "(")
		if end <= start {
			continue
		}
		name := string(b[start+1 : end])
		fields := strings.Fields(string(b[end+1:]))
		if len(fields) < 22 {
			continue
		}
		ticks := number(fields[11]) + number(fields[12])
		born := number(fields[19])
		sample := processSample{Ticks: ticks, Start: born}
		next[pid] = sample
		p := protocol.Process{PID: pid, Name: name, RAM: number(fields[21]) * uint64(os.Getpagesize()), Uptime: uptime - float64(born)/s.hz, Engine: strings.Contains(strings.ToLower(name), "backhaul")}
		if old, ok := s.process[pid]; ok && old.Start == born && ticks >= old.Ticks && delta > 0 && delta <= 120 {
			cpu := 100 * float64(ticks-old.Ticks) / s.hz / delta
			p.CPU = &cpu
		}
		d.Processes = append(d.Processes, p)
	}
	s.process = next
	sort.Slice(d.Processes, func(i, j int) bool {
		if d.Processes[i].Engine != d.Processes[j].Engine {
			return d.Processes[i].Engine
		}
		return d.Processes[i].RAM > d.Processes[j].RAM
	})
	if len(d.Processes) > 150 {
		d.Processes = d.Processes[:150]
		d.Errors = append(d.Errors, "Process list: engines first, then largest memory; limited to 150.")
	}
	if b, e := command(ctx, "ss", "-H", "-lntup"); e == nil {
		pidPattern := regexp.MustCompile(`pid=(\d+)`)
		procPattern := regexp.MustCompile(`"([^"]+)"`)
		scan := bufio.NewScanner(bytes.NewReader(b))
		for scan.Scan() {
			line := scan.Text()
			f := strings.Fields(line)
			if len(f) < 5 {
				continue
			}
			pid := 0
			if m := pidPattern.FindStringSubmatch(line); len(m) == 2 {
				pid, _ = strconv.Atoi(m[1])
			}
			proc := ""
			if m := procPattern.FindStringSubmatch(line); len(m) == 2 {
				proc = m[1]
			}
			d.Listeners = append(d.Listeners, protocol.Listener{Address: f[4], Protocol: f[0], PID: pid, Process: proc})
			if len(d.Listeners) >= 5000 {
				d.Errors = append(d.Errors, "Listener scan exceeded 5000 observations.")
				break
			}
		}
		enginePIDs := map[int]bool{}
		for _, p := range d.Processes {
			if p.Engine {
				enginePIDs[p.PID] = true
			}
		}
		sort.SliceStable(d.Listeners, func(i, j int) bool {
			a, b := d.Listeners[i], d.Listeners[j]
			if enginePIDs[a.PID] != enginePIDs[b.PID] {
				return enginePIDs[a.PID]
			}
			if a.Protocol != b.Protocol {
				return a.Protocol == "tcp"
			}
			return a.Address < b.Address
		})
		if len(d.Listeners) > 300 {
			d.Listeners = d.Listeners[:300]
			d.Errors = append(d.Errors, "Listener list limited to 300; engine processes and TCP prioritized.")
		}
	} else {
		d.Errors = append(d.Errors, "Listener collection unavailable; install iproute2.")
	}
	if b, e := command(ctx, "ss", "-H", "-tan"); e == nil {
		d.SocketStates = map[string]int{}
		scan := bufio.NewScanner(bytes.NewReader(b))
		count := 0
		for scan.Scan() {
			f := strings.Fields(scan.Text())
			if len(f) > 0 {
				d.SocketStates[f[0]]++
				count++
				if count > 10000 {
					d.Errors = append(d.Errors, "TCP state counts truncated after 10000 sockets.")
					break
				}
			}
		}
	}
	if b, e := command(ctx, "systemctl", "list-units", "--type=service", "--all", "--plain", "--no-legend", "--no-pager"); e == nil {
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) < 4 {
				continue
			}
			n := f[0]
			if !strings.Contains(n, "backhaul") && !strings.HasPrefix(n, "tunnelmanager-") {
				continue
			}
			d.Services = append(d.Services, protocol.Service{Name: n, Active: f[2], Enabled: "not observed"})
			if len(d.Services) >= 100 {
				break
			}
		}
	} else {
		d.Errors = append(d.Errors, "systemd observations unavailable.")
	}
	if b, e := command(ctx, "systemctl", "list-unit-files", "--type=service", "--no-legend", "--no-pager"); e == nil {
		enabled := map[string]string{}
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				enabled[f[0]] = f[1]
			}
		}
		for i := range d.Services {
			if v, ok := enabled[d.Services[i].Name]; ok {
				d.Services[i].Enabled = v
			}
		}
	}
	s.at = now
	return d
}
