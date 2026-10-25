package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Zand3rsCode/rerust-agent/internal/jail"
	"github.com/Zand3rsCode/rerust-agent/internal/sysstats"
)

// KeepLogs previous sessions' logs are kept next to server.log; MaxArgs launch arguments at most.
const (
	KeepLogs = 10
	MaxArgs  = 200
)

/* ---------- /proc helpers ---------- */

// exeOf is /proc/<pid>/exe without " (deleted)"; "" when gone, a zombie or not readable.
func exeOf(pid int) string {
	if pid <= 0 {
		return ""
	}
	target, err := os.Readlink(sysstats.Proc + "/" + strconv.Itoa(pid) + "/exe")
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(target, " (deleted)")
}

func cwdOf(pid int) string {
	target, err := os.Readlink(sysstats.Proc + "/" + strconv.Itoa(pid) + "/cwd")
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(target, " (deleted)")
}

// running: alive and not a zombie.
func running(pid int) bool {
	raw, err := os.ReadFile(sysstats.Proc + "/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if v, ok := strings.CutPrefix(line, "State:"); ok {
			return !strings.HasPrefix(strings.TrimSpace(v), "Z")
		}
	}
	return true
}

func commandLine(pid int) []string {
	if pid <= 0 || !running(pid) || exeOf(pid) == "" {
		return nil
	}
	raw, err := os.ReadFile(sysstats.Proc + "/" + strconv.Itoa(pid) + "/cmdline")
	if err != nil || len(raw) == 0 {
		return nil
	}
	return strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
}

func allPIDs() []int {
	var out []int
	entries, _ := os.ReadDir(sysstats.Proc)
	for _, e := range entries {
		if pid, err := strconv.Atoi(e.Name()); err == nil && e.IsDir() {
			out = append(out, pid)
		}
	}
	sort.Ints(out)
	return out
}

func realOr(path string) string {
	if real, err := filepath.EvalSymlinks(path); err == nil {
		return real
	}
	return path
}

// findByExecutable is every running process of this exact binary.
func findByExecutable(path string) []int {
	want := realOr(path)
	out := []int{}
	for _, pid := range allPIDs() {
		if exeOf(pid) == want && running(pid) {
			out = append(out, pid)
		}
	}
	return out
}

// rustInfo is {pid, memory_kb} when pid is a live RustDedicated (comm is cut to 15 characters by the kernel).
func rustInfo(pid int) map[string]any {
	raw, err := os.ReadFile(sysstats.Proc + "/" + strconv.Itoa(pid) + "/comm")
	if err != nil || strings.TrimSpace(string(raw)) != Executable[:min(len(Executable), 15)] || !running(pid) {
		return nil
	}
	kb := sysstats.RSSBytes(pid) / 1024
	if kb < 0 {
		kb = 0
	}
	return map[string]any{"pid": pid, "memory_kb": kb}
}

// owns: pid runs this server's own RustDedicated (started from its folder) - PIDs are reused.
func (s *Server) owns(pid int) bool {
	exe := exeOf(pid)
	return exe != "" && (exe == s.Exe() || exe == realOr(s.Exe()))
}

// killGroup signals the process group when pid leads one (everything the agent starts runs under setsid), else
// only pid.
func killGroup(pid int, sig syscall.Signal) {
	if pid <= 1 {
		return
	}
	if pgid, err := syscall.Getpgid(pid); err == nil && pgid == pid {
		_ = syscall.Kill(-pid, sig)
		return
	}
	_ = syscall.Kill(pid, sig)
}

/* ---------- start ---------- */

// environment: the game's native plugin folder on the library path (as Facepunch's runds.sh), and Carbon through
// Unity Doorstop (LD_PRELOAD on the binary only - there is no shell in between, so Doorstop's dup2 hook can't break
// the output redirection as it did with the PHP agent's bash launcher).
func (s *Server) environment(carbon bool) []string {
	dir := s.Dir()
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "LD_PRELOAD=") && !strings.HasPrefix(kv, "LD_LIBRARY_PATH=") && !strings.HasPrefix(kv, "DOORSTOP_") {
			env = append(env, kv)
		}
	}
	env = append(env, "LD_LIBRARY_PATH="+dir+":"+dir+"/RustDedicated_Data/Plugins/x86_64", "TERM=xterm")
	if carbon && jail.IsFile(dir+"/libdoorstop.so") {
		env = append(env, "DOORSTOP_ENABLED=1", "DOORSTOP_TARGET_ASSEMBLY="+dir+"/carbon/managed/Carbon.Preloader.dll", "LD_PRELOAD="+dir+"/libdoorstop.so")
	}
	return env
}

// rotateLog: Rust overwrites server.log on every start; the previous one becomes server-YYYYmmdd-HHMMSS.log (its
// last write time) and only the newest KeepLogs stay.
func (s *Server) rotateLog() {
	log := s.LogPath()
	if info, err := os.Stat(log); err == nil && info.Mode().IsRegular() && info.Size() > 0 {
		base := s.LogDir() + "/server-" + info.ModTime().Format("20060102-150405")
		target := base + ".log"
		for n := 2; fileExists(target) && n < 100; n++ {
			target = fmt.Sprintf("%s-%d.log", base, n)
		}
		_ = os.Rename(log, target)
	}
	old, _ := filepath.Glob(s.LogDir() + "/server-*.log")
	sort.Sort(sort.Reverse(sort.StringSlice(old)))
	for i, f := range old {
		if i >= KeepLogs && rotatedLog.MatchString(filepath.Base(f)) {
			_ = os.Remove(f)
		}
	}
}

func fileExists(path string) bool { _, err := os.Lstat(path); return err == nil }

// start launches RustDedicated detached (own session) and returns its PID.
func (a *Agent) start(s *Server, args []string, carbon bool) (int, error) {
	if !s.Installed() {
		return 0, fmt.Errorf("%s not found in %s. Install the server first", Executable, s.Dir())
	}
	if len(args) > MaxArgs {
		return 0, errors.New("too many arguments")
	}
	for _, arg := range args {
		if len(arg) > 2048 || strings.ContainsAny(arg, "\x00\r\n") || strings.EqualFold(arg, "-logfile") {
			return 0, errors.New("invalid launch argument")
		}
	}
	if info, err := os.Stat(s.Exe()); err != nil || info.Mode()&0o111 == 0 {
		return 0, fmt.Errorf("%s is not executable (chmod +x)", s.Exe())
	}
	s.rotateLog()

	// What the process prints (Carbon's preloader writes only to stdout): readable by the agent only - it holds the
	// command line with the RCON password.
	out, err := os.OpenFile(s.OutputPath(), os.O_CREATE|os.O_WRONLY|os.O_TRUNC|os.O_APPEND, 0o600)
	if err != nil {
		return 0, fmt.Errorf("could not create %s", s.OutputPath())
	}
	defer out.Close()
	_ = os.Chmod(s.OutputPath(), 0o600)

	cmd := exec.Command(s.Exe(), append([]string{"-logfile", s.LogPath()}, args...)...)
	cmd.Dir = s.Dir()
	cmd.Env = s.environment(carbon)
	cmd.Stdout, cmd.Stderr = out, out
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("server did not start: %v", err)
	}
	pid := cmd.Process.Pid
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }() // reap it whenever it ends
	select {
	case <-exited:
		return 0, fmt.Errorf("%s exited immediately after starting (check its log)", Executable)
	case <-time.After(500 * time.Millisecond):
	}
	recordStart(s, args)
	return pid, nil
}

// recordStart keeps the arguments of the last start (without the RCON password) for taking the server over later.
func recordStart(s *Server, args []string) {
	kept := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		if args[i] == "+rcon.password" {
			i++ // never on disk outside the panel's database
			continue
		}
		kept = append(kept, args[i])
	}
	raw, _ := json.Marshal(map[string]any{"args": kept, "at": time.Now().Unix()})
	_ = os.WriteFile(s.LogDir()+"/last-start.json", raw, 0o640)
}

func lastStart(state, slug string) any {
	raw, err := os.ReadFile(logDirFor(state, slug) + "/last-start.json")
	if err != nil {
		return nil
	}
	var d struct {
		Args []any `json:"args"`
		At   int64 `json:"at"`
	}
	if json.Unmarshal(raw, &d) != nil || d.Args == nil {
		return nil
	}
	args := []string{}
	for _, v := range d.Args {
		if s, ok := v.(string); ok {
			args = append(args, s)
		}
	}
	return map[string]any{"args": args, "at": d.At}
}

/* ---------- handlers ---------- */

func (a *Agent) processStart(w http.ResponseWriter, r *http.Request, s *Server) {
	in, ok := parse(w, r)
	if !ok {
		return
	}
	args, okArgs := in.strings("args")
	carbon, okCarbon := in.boolean("carbon")
	if !okArgs || !okCarbon {
		invalid(w, "args (a list of strings) and carbon (true/false) are required.")
		return
	}
	pid, err := a.start(s, args, carbon)
	if err != nil {
		fail(w, 409, "start_failed", upperFirst(err.Error())+".")
		return
	}
	writeJSON(w, 200, map[string]any{"pid": pid})
}

func (a *Agent) processInfo(w http.ResponseWriter, r *http.Request, s *Server) {
	in, _ := readInput(r)
	pid, ok := in.integer("pid")
	if !ok || pid < 1 {
		invalid(w, "The pid field is required.")
		return
	}
	if info := a.info(s, int(pid), in.truthy("fresh")); info != nil {
		writeJSON(w, 200, info)
		return
	}
	writeJSON(w, 200, map[string]any{"pid": nil})
}

// info: this server's running RustDedicated with this PID, or nil. A recent monitor sample proves it alive cheaply;
// a miss is not trusted (the process may be newer than the sample).
func (a *Agent) info(s *Server, pid int, fresh bool) map[string]any {
	if !s.owns(pid) {
		return nil
	}
	if !fresh {
		if p, ok := a.Stats.RecentProcess(pid, 6); ok {
			return map[string]any{"pid": pid, "memory_kb": p.MemBytes / 1024}
		}
	}
	return rustInfo(pid)
}

func (a *Agent) processFind(w http.ResponseWriter, r *http.Request, s *Server) {
	writeJSON(w, 200, map[string]any{"pids": findByExecutable(s.Exe())})
}

// assertOwn refuses a running RustDedicated of another server; a PID that is gone or not a Rust server passes.
func assertOwn(s *Server, pid int) error {
	if !s.owns(pid) && rustInfo(pid) != nil {
		return fmt.Errorf("process %d belongs to another server", pid)
	}
	return nil
}

func (a *Agent) processKill(w http.ResponseWriter, r *http.Request, s *Server) {
	in, ok := parse(w, r)
	if !ok {
		return
	}
	pid, okPid := in.integer("pid")
	if !okPid || pid < 1 {
		invalid(w, "The pid field is required.")
		return
	}
	if err := assertOwn(s, int(pid)); err != nil {
		fail(w, 409, "not_this_server", upperFirst(err.Error())+".")
		return
	}
	if rustInfo(int(pid)) == nil {
		writeJSON(w, 200, map[string]any{"killed": false})
		return
	}
	killGroup(int(pid), syscall.SIGKILL) // no verified SIGTERM save in Rust: the panel saves over RCON first
	writeJSON(w, 200, map[string]any{"killed": true})
}

func (a *Agent) processAffinity(w http.ResponseWriter, r *http.Request, s *Server) {
	in, ok := parse(w, r)
	if !ok {
		return
	}
	pid, okPid := in.integer("pid")
	list, okCores := in.ints("cores")
	if !okPid || pid < 1 || !okCores || len(list) > 256 {
		invalid(w, "pid and cores (a list) are required.")
		return
	}
	if err := assertOwn(s, int(pid)); err != nil {
		fail(w, 409, "refused", upperFirst(err.Error())+".")
		return
	}
	if a.info(s, int(pid), true) == nil {
		writeJSON(w, 200, map[string]any{"applied": false})
		return
	}
	count := cores()
	parts := []string{}
	for _, c := range list {
		if c < 0 || c >= int64(count) {
			fail(w, 409, "refused", fmt.Sprintf("This machine has no core %d.", c))
			return
		}
		parts = append(parts, strconv.FormatInt(c, 10))
	}
	spec := strings.Join(parts, ",")
	if spec == "" {
		spec = fmt.Sprintf("0-%d", max(0, count-1))
	}
	// -a: every thread of the process.
	if out, err := exec.Command("taskset", "-a", "-p", "-c", spec, strconv.Itoa(int(pid))).CombinedOutput(); err != nil {
		fail(w, 409, "refused", "Could not set CPU affinity: "+strings.TrimSpace(string(out)))
		return
	}
	writeJSON(w, 200, map[string]any{"applied": true})
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
