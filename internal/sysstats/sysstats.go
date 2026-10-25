// Package sysstats samples this machine from /proc every few seconds (CPU, memory, network, disks, RustDedicated and
// node processes) and keeps the latest snapshot plus ~10 minutes of history - the same numbers and JSON shape as the
// ReRust panel's SystemStats, so the panel's dashboard reads both agents alike.
package sysstats

import (
	"bufio"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// HistoryPoints is ~10 minutes at a 3 second interval; StaleAfter = seconds without a sample = not fresh.
const (
	HistoryPoints = 200
	StaleAfter    = 30
	Interval      = 3 * time.Second
)

var skipFS = map[string]bool{}

func init() {
	for _, fs := range strings.Fields("proc sysfs devtmpfs devpts tmpfs cgroup cgroup2 overlay squashfs securityfs pstore debugfs tracefs mqueue hugetlbfs fusectl configfs autofs binfmt_misc nsfs ramfs rpc_pipefs bpf efivarfs fuse.gvfsd-fuse fuse.portal nfsd") {
		skipFS[fs] = true
	}
}

type procUse struct {
	cpu float64 // seconds of CPU time
	mem int64   // bytes
}

type netIf struct {
	name   string
	rx, tx int64
}

type disk struct {
	mount, label string
	size, free   int64
}

type sample struct {
	wall            float64
	os              string
	cores           int
	boot            int64
	cpuIdle, cpuAll float64
	memTotal        int64
	memAvailable    int64
	net             []netIf
	disks           []disk
	procs           map[int]procUse
	node            map[int]procUse
}

// Proc is the /proc root (tests point it at fixtures).
var Proc = "/proc"

const clockTicks = 100.0

func read(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

func take() *sample {
	stat := read(Proc + "/stat")
	meminfo := read(Proc + "/meminfo")
	if stat == "" || meminfo == "" {
		return nil
	}
	s := &sample{wall: float64(time.Now().UnixNano()) / 1e9, os: osName()}
	for _, line := range strings.Split(stat, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		switch {
		case f[0] == "cpu":
			var v [8]float64
			for i := 0; i < 8 && i+1 < len(f); i++ {
				v[i], _ = strconv.ParseFloat(f[i+1], 64)
			}
			for _, x := range v {
				s.cpuAll += x
			}
			s.cpuIdle = v[3] + v[4]
		case strings.HasPrefix(f[0], "cpu"):
			s.cores++
		case f[0] == "btime" && len(f) > 1:
			s.boot, _ = strconv.ParseInt(f[1], 10, 64)
		}
	}
	if s.cores < 1 {
		s.cores = 1
	}
	kb := func(key string) int64 {
		for _, line := range strings.Split(meminfo, "\n") {
			if strings.HasPrefix(line, key+":") {
				f := strings.Fields(line)
				if len(f) >= 2 {
					n, _ := strconv.ParseInt(f[1], 10, 64)
					return n * 1024
				}
			}
		}
		return -1
	}
	s.memTotal = max(kb("MemTotal"), 0)
	s.memAvailable = kb("MemAvailable")
	if s.memAvailable < 0 {
		s.memAvailable = max(kb("MemFree"), 0) + max(kb("Buffers"), 0) + max(kb("Cached"), 0)
	}
	s.net = network()
	s.disks = disks()
	s.procs = processes(func(comm string) bool { return strings.HasPrefix(comm, "RustDedicated") })
	s.node = processes(func(comm string) bool { return comm == "node" || comm == "nodejs" })
	return s
}

func network() []netIf {
	var out []netIf
	lines := strings.Split(read(Proc+"/net/dev"), "\n")
	if len(lines) < 3 {
		return out
	}
	for _, line := range lines[2:] {
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		cols := strings.Fields(rest)
		if name == "lo" || len(cols) < 9 {
			continue
		}
		rx, _ := strconv.ParseInt(cols[0], 10, 64)
		tx, _ := strconv.ParseInt(cols[8], 10, 64)
		out = append(out, netIf{name, rx, tx})
	}
	return out
}

func disks() []disk {
	var out []disk
	seen := map[string]bool{}
	for _, line := range strings.Split(read(Proc+"/mounts"), "\n") {
		f := strings.Split(line, " ")
		if len(f) < 3 {
			continue
		}
		device, mount, fs := f[0], strings.ReplaceAll(f[1], `\040`, " "), f[2]
		if skipFS[fs] || !strings.HasPrefix(device, "/") || seen[device] {
			continue
		}
		var st syscall.Statfs_t
		if syscall.Statfs(mount, &st) != nil || st.Blocks == 0 {
			continue
		}
		seen[device] = true
		bs := int64(st.Bsize)
		out = append(out, disk{mount: mount, label: filepath.Base(device), size: int64(st.Blocks) * bs, free: int64(st.Bavail) * bs})
	}
	return out
}

func processes(wanted func(string) bool) map[int]procUse {
	out := map[int]procUse{}
	entries, _ := os.ReadDir(Proc)
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || !e.IsDir() {
			continue
		}
		dir := Proc + "/" + e.Name()
		comm := strings.TrimSpace(read(dir + "/comm"))
		if comm == "" || !wanted(comm) {
			continue
		}
		stat := read(dir + "/stat")
		i := strings.LastIndex(stat, ")")
		if i < 0 || i+2 > len(stat) {
			continue
		}
		f := strings.Fields(stat[i+2:])
		if len(f) < 22 {
			continue
		}
		ut, _ := strconv.ParseFloat(f[11], 64)
		st, _ := strconv.ParseFloat(f[12], 64)
		rss := RSSBytes(pid)
		if rss < 0 {
			pages, _ := strconv.ParseInt(f[21], 10, 64)
			rss = pages * 4096
		}
		out[pid] = procUse{cpu: (ut + st) / clockTicks, mem: rss}
	}
	return out
}

// RSSBytes is VmRSS of a process, -1 when unknown.
func RSSBytes(pid int) int64 {
	sc := bufio.NewScanner(strings.NewReader(read(Proc + "/" + strconv.Itoa(pid) + "/status")))
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "VmRSS:") {
			f := strings.Fields(sc.Text())
			if len(f) >= 2 {
				n, _ := strconv.ParseInt(f[1], 10, 64)
				return n * 1024
			}
		}
	}
	return -1
}

func osName() string {
	for _, line := range strings.Split(read("/etc/os-release"), "\n") {
		if v, ok := strings.CutPrefix(line, "PRETTY_NAME="); ok {
			return strings.Trim(v, `"`)
		}
	}
	return "Linux"
}

// Snapshot is the panel's SystemStats snapshot shape.
type Snapshot struct {
	SampledAt     int64              `json:"sampled_at"`
	OS            string             `json:"os"`
	Cores         int                `json:"cores"`
	Uptime        *int64             `json:"uptime"`
	CPUPercent    *float64           `json:"cpu_percent"`
	Memory        Memory             `json:"memory"`
	Network       Network            `json:"network"`
	Disks         []Disk             `json:"disks"`
	Processes     map[string]Process `json:"processes"`
	NodeProcesses map[string]Process `json:"node_processes"`
}

type Memory struct {
	Total   int64    `json:"total"`
	Used    int64    `json:"used"`
	Percent *float64 `json:"percent"`
}

type Network struct {
	RX         *float64    `json:"rx"`
	TX         *float64    `json:"tx"`
	Interfaces []Interface `json:"interfaces"`
}

type Interface struct {
	Name string   `json:"name"`
	RX   *float64 `json:"rx"`
	TX   *float64 `json:"tx"`
}

type Disk struct {
	Mount       string   `json:"mount"`
	Label       string   `json:"label"`
	Size        int64    `json:"size"`
	Free        int64    `json:"free"`
	UsedPercent *float64 `json:"used_percent"`
}

type Process struct {
	CPUPercent *float64 `json:"cpu_percent"`
	CPUCores   *float64 `json:"cpu_cores"`
	MemBytes   int64    `json:"mem_bytes"`
	MemPercent *float64 `json:"mem_percent"`
}

// Point is one history entry.
type Point struct {
	T   int64    `json:"t"`
	CPU *float64 `json:"cpu"`
	Mem *float64 `json:"mem"`
	RX  *float64 `json:"rx"`
	TX  *float64 `json:"tx"`
}

func ptr(v float64) *float64 { return &v }

func round(v float64, places int) float64 {
	p := math.Pow(10, float64(places))
	return math.Round(v*p) / p
}

func clamp(v, lo, hi float64) float64 { return math.Max(lo, math.Min(hi, v)) }

func compute(prev *sample, cur *sample) Snapshot {
	var dt float64
	if prev != nil {
		dt = math.Max(0.001, cur.wall-prev.wall)
	}
	snap := Snapshot{SampledAt: time.Now().Unix(), OS: cur.os, Cores: cur.cores}
	if cur.boot > 0 {
		up := max(0, time.Now().Unix()-cur.boot)
		snap.Uptime = &up
	}
	if prev != nil {
		dTotal := cur.cpuAll - prev.cpuAll
		dIdle := cur.cpuIdle - prev.cpuIdle
		if dTotal > 0 {
			snap.CPUPercent = ptr(round(clamp((1-dIdle/dTotal)*100, 0, 100), 1))
		}
	}
	used := max(0, cur.memTotal-cur.memAvailable)
	snap.Memory = Memory{Total: cur.memTotal, Used: used}
	if cur.memTotal > 0 {
		snap.Memory.Percent = ptr(round(float64(used)/float64(cur.memTotal)*100, 1))
	}

	prevNet := map[string]netIf{}
	if prev != nil {
		for _, n := range prev.net {
			prevNet[n.name] = n
		}
	}
	var rx, tx float64
	ifs := []Interface{}
	for _, n := range cur.net {
		i := Interface{Name: n.name}
		if p, ok := prevNet[n.name]; ok && dt > 0 {
			i.RX = ptr(math.Max(0, float64(n.rx-p.rx)/dt))
			i.TX = ptr(math.Max(0, float64(n.tx-p.tx)/dt))
			rx += *i.RX
			tx += *i.TX
		}
		ifs = append(ifs, i)
	}
	val := func(p *float64) float64 {
		if p == nil {
			return 0
		}
		return *p
	}
	sort.SliceStable(ifs, func(a, b int) bool { return val(ifs[a].RX)+val(ifs[a].TX) > val(ifs[b].RX)+val(ifs[b].TX) })
	if len(ifs) > 8 {
		ifs = ifs[:8]
	}
	snap.Network = Network{Interfaces: ifs}
	if prev != nil {
		snap.Network.RX, snap.Network.TX = ptr(math.Round(rx)), ptr(math.Round(tx))
	}

	snap.Disks = []Disk{}
	for _, d := range cur.disks {
		out := Disk{Mount: d.mount, Label: d.label, Size: d.size, Free: d.free}
		if d.size > 0 {
			out.UsedPercent = ptr(round(float64(d.size-d.free)/float64(d.size)*100, 1))
		}
		snap.Disks = append(snap.Disks, out)
	}
	var prevProcs, prevNode map[int]procUse
	if prev != nil {
		prevProcs, prevNode = prev.procs, prev.node
	}
	snap.Processes = usage(cur.procs, prevProcs, dt, cur.cores, cur.memTotal)
	snap.NodeProcesses = usage(cur.node, prevNode, dt, cur.cores, cur.memTotal)
	return snap
}

func usage(cur, prev map[int]procUse, dt float64, cores int, memTotal int64) map[string]Process {
	out := map[string]Process{}
	for pid, p := range cur {
		proc := Process{MemBytes: p.mem}
		if before, ok := prev[pid]; ok && dt > 0 {
			pct := (p.cpu - before.cpu) / (dt * float64(cores)) * 100
			proc.CPUPercent = ptr(round(clamp(pct, 0, 100), 1))
			proc.CPUCores = ptr(round(math.Max(0, pct)*float64(cores)/100, 2))
		}
		if memTotal > 0 {
			proc.MemPercent = ptr(round(float64(p.mem)/float64(memTotal)*100, 1))
		}
		out[strconv.Itoa(pid)] = proc
	}
	return out
}

// Sampler keeps the latest snapshot and the history.
type Sampler struct {
	mu      sync.Mutex
	prev    *sample
	latest  *Snapshot
	history []Point
}

// Run samples every Interval until stop is closed.
func (s *Sampler) Run(stop <-chan struct{}) {
	s.Sample()
	t := time.NewTicker(Interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			s.Sample()
		}
	}
}

// Sample takes one sample now.
func (s *Sampler) Sample() {
	cur := take()
	if cur == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := compute(s.prev, cur)
	s.prev = cur
	s.latest = &snap
	if snap.CPUPercent != nil {
		s.history = append(s.history, Point{T: snap.SampledAt, CPU: snap.CPUPercent, Mem: snap.Memory.Percent, RX: snap.Network.RX, TX: snap.Network.TX})
		if len(s.history) > HistoryPoints {
			s.history = s.history[len(s.history)-HistoryPoints:]
		}
	}
}

// Latest is the newest snapshot (nil before the first sample).
func (s *Sampler) Latest() *Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.latest
}

// History is a copy of the history.
func (s *Sampler) History() []Point {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Point{}, s.history...)
}

// Fresh is true when the newest snapshot is recent.
func (s *Sampler) Fresh() bool {
	l := s.Latest()
	return l != nil && time.Now().Unix()-l.SampledAt <= StaleAfter
}

// RecentProcess is a RustDedicated process from a sample at most maxAge seconds old.
func (s *Sampler) RecentProcess(pid int, maxAge int64) (Process, bool) {
	l := s.Latest()
	if l == nil || time.Now().Unix()-l.SampledAt > maxAge {
		return Process{}, false
	}
	p, ok := l.Processes[strconv.Itoa(pid)]
	return p, ok
}
