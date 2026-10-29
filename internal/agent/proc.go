package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Zand3rsCode/rerust-agent/internal/jail"
	"github.com/Zand3rsCode/rerust-agent/internal/sysstats"
)

// KeepLogs previous sessions' logs are kept; MaxArgs launch arguments at most.
const (
	KeepLogs = 10
	MaxArgs  = 200
)

// Inside each server folder: what the game writes (logs) and what its launcher reads. The game owns the folder, so
// nothing here is trusted by the agent - it is read through the jail like every other file there.
const (
	gameDir    = ".rerust"
	launchFile = gameDir + "/launch.json"
	serverLog  = gameDir + "/server.log"
	outputLog  = gameDir + "/output.log"
	oldLogs    = gameDir + "/logs"
)

func procRoot() string { return sysstats.Proc }

// LaunchSpec is what the launcher (rerust-agent launch, inside the server's unit) starts.
type LaunchSpec struct {
	Args   []string `json:"args"`
	Carbon bool     `json:"carbon"`
}

func validArgs(args []string) error {
	if len(args) > MaxArgs {
		return errors.New("too many arguments")
	}
	for _, arg := range args {
		if len(arg) > 2048 || strings.ContainsAny(arg, "\x00\r\n") || strings.EqualFold(arg, "-logfile") {
			return errors.New("invalid launch argument")
		}
	}
	return nil
}

// Launch runs inside rerust-server@<slug>.service as the game user, in the server's sandbox (it sees only its own
// folder): read launch.json, send output to .rerust/output.log, set Rust's library path (and Carbon's Doorstop),
// then become RustDedicated (exec - the unit's main process is the game itself).
func Launch(dir string) error {
	raw, err := os.ReadFile(dir + "/" + launchFile)
	if err != nil {
		return fmt.Errorf("no launch file: %v", err)
	}
	var spec LaunchSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return fmt.Errorf("launch file: %v", err)
	}
	if err := validArgs(spec.Args); err != nil {
		return err
	}
	exe := dir + "/" + Executable
	if err := os.MkdirAll(dir+"/"+gameDir+"/home", 0o770); err != nil {
		return err
	}
	out, err := os.OpenFile(dir+"/"+outputLog, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|syscall.O_NOFOLLOW, 0o640)
	if err != nil {
		return fmt.Errorf("output log: %v", err)
	}
	if err := syscall.Dup3(int(out.Fd()), 1, 0); err != nil {
		return err
	}
	if err := syscall.Dup3(int(out.Fd()), 2, 0); err != nil {
		return err
	}
	if err := os.Chdir(dir); err != nil {
		return err
	}
	env := []string{
		"HOME=" + dir + "/" + gameDir + "/home",
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"TERM=xterm",
		"LANG=C.UTF-8",
		"LD_LIBRARY_PATH=" + dir + ":" + dir + "/RustDedicated_Data/Plugins/x86_64",
	}
	if spec.Carbon {
		if info, err := os.Stat(dir + "/libdoorstop.so"); err == nil && info.Mode().IsRegular() {
			env = append(env, "DOORSTOP_ENABLED=1", "DOORSTOP_TARGET_ASSEMBLY="+dir+"/carbon/managed/Carbon.Preloader.dll", "LD_PRELOAD="+dir+"/libdoorstop.so")
		}
	}
	argv := append([]string{exe, "-logfile", dir + "/" + serverLog}, spec.Args...)
	return syscall.Exec(exe, argv, env)
}

// rotateLog: Rust overwrites server.log on every start; the previous one becomes .rerust/logs/server-<time>.log and
// only the newest KeepLogs stay. All through the jail.
func (a *Agent) rotateLog(j *jail.Jail) {
	if info, err := j.Lstat(serverLog); err == nil && info.Mode().IsRegular() && info.Size() > 0 {
		if _, err := j.MkdirAll(oldLogs); err == nil {
			base := oldLogs + "/server-" + info.ModTime().Format("20060102-150405")
			target := base + ".log"
			for n := 2; j.IsFile(target) && n < 100; n++ {
				target = fmt.Sprintf("%s-%d.log", base, n)
			}
			_ = j.Rename(serverLog, target)
		}
	}
	entries, _ := j.ReadDir(oldLogs)
	var names []string
	for _, e := range entries {
		if rotatedLog.MatchString(e.Name()) {
			names = append(names, e.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	for i, n := range names {
		if i >= KeepLogs {
			_ = j.Remove(oldLogs + "/" + n)
		}
	}
}

// start writes the launch file and has systemd start the server's unit.
func (a *Agent) start(s *Server, args []string, carbon bool) (int, error) {
	if err := validArgs(args); err != nil {
		return 0, err
	}
	j, err := jail.Open(s.Dir())
	if err != nil {
		return 0, fmt.Errorf("%s not found in %s. Install the server first", Executable, s.Dir())
	}
	defer j.Close()
	if info, err := j.Lstat(Executable); err != nil || !info.Mode().IsRegular() {
		return 0, fmt.Errorf("%s not found in %s. Install the server first", Executable, s.Dir())
	} else if info.Mode()&0o111 == 0 {
		return 0, fmt.Errorf("%s is not executable (chmod +x)", Executable)
	}
	if pid := a.waitLeaving(s.Slug); pid > 0 {
		if !running(pid) {
			log.Printf("%s: the old process %d was still shutting down after %s", s.Slug, pid, LeaveWait)
		}
		return 0, fmt.Errorf("the server is already running (process %d)", pid)
	}
	if _, err := j.MkdirAll(gameDir); err != nil {
		return 0, err
	}
	a.rotateLog(j)
	raw, _ := json.Marshal(LaunchSpec{Args: args, Carbon: carbon})
	if err := j.WriteAtomic(launchFile, raw, 0o640); err != nil {
		return 0, err
	}
	pid, err := a.sup.Start(s.Slug)
	if err != nil {
		return 0, err
	}
	recordStart(s, args)
	return pid, nil
}

// LeaveWait is how long a start waits for a server that is still shutting down - short: the panel gives the whole
// start call 10 s and tries again itself. A variable only for tests.
var LeaveWait = 5 * time.Second

// waitLeaving returns the unit's running process, 0 when there is none. A RustDedicated that quit shows as a zombie
// in /proc while its other threads still shut down, and systemd keeps it as the unit's process until all of them
// have ended - a start right after a stop (daily restart) waits for that instead of refusing.
func (a *Agent) waitLeaving(slug string) int {
	began := time.Now()
	deadline := began.Add(LeaveWait)
	waited := 0
	for {
		pid := a.sup.MainPID(slug)
		if pid <= 0 && waited > 0 {
			log.Printf("%s: waited %s for the old process %d to end", slug, time.Since(began).Round(10*time.Millisecond), waited)
		}
		if pid <= 0 || running(pid) || !time.Now().Before(deadline) {
			return pid
		}
		waited = pid
		time.Sleep(250 * time.Millisecond)
	}
}

// recordStart keeps the arguments of the last start (without the RCON password) in the agent's own folder.
func recordStart(s *Server, args []string) {
	kept := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		if strings.EqualFold(strings.TrimLeft(args[i], "+-"), "rcon.password") {
			i++ // never on disk outside the panel's database
			continue
		}
		kept = append(kept, args[i])
	}
	raw, _ := json.Marshal(map[string]any{"args": kept, "at": time.Now().Unix()})
	_ = os.WriteFile(s.LogDir()+"/last-start.json", raw, 0o600)
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

/* ---------- /proc (read-only: the game runs as another user) ---------- */

func running(pid int) bool {
	raw, err := os.ReadFile(procRoot() + "/" + strconv.Itoa(pid) + "/status")
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

// rustInfo is {pid, memory_kb} when pid is a live RustDedicated.
func rustInfo(pid int) map[string]any {
	if pid <= 0 || procComm(pid) != commName || !running(pid) {
		return nil
	}
	kb := max(sysstats.RSSBytes(pid)/1024, 0)
	return map[string]any{"pid": pid, "memory_kb": kb}
}

// commandLine of a process (world-readable in /proc).
func commandLine(pid int) []string {
	if pid <= 0 || !running(pid) {
		return nil
	}
	raw, err := os.ReadFile(procRoot() + "/" + strconv.Itoa(pid) + "/cmdline")
	if err != nil || len(raw) == 0 {
		return nil
	}
	return strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
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
		log.Printf("%s: start refused: %v", s.Slug, err)
		fail(w, 409, "start_failed", upperFirst(err.Error())+".")
		return
	}
	log.Printf("%s: started (process %d)", s.Slug, pid)
	writeJSON(w, 200, map[string]any{"pid": pid})
}

// info: this server's running RustDedicated with this PID (the unit's own process), or nil.
func (a *Agent) info(s *Server, pid int, fresh bool) map[string]any {
	if pid <= 0 || a.sup.MainPID(s.Slug) != pid {
		return nil
	}
	if !fresh {
		if p, ok := a.Stats.RecentProcess(pid, 6); ok {
			return map[string]any{"pid": pid, "memory_kb": p.MemBytes / 1024}
		}
	}
	if info := rustInfo(pid); info != nil || !fresh {
		return info
	}
	// Still the unit's process but a zombie: Rust is shutting down - not gone until systemd lets go of it.
	if procComm(pid) == commName {
		if _, seen := a.leaving.LoadOrStore(pid, true); !seen {
			log.Printf("%s: process %d quit, waiting for its last threads to end", s.Slug, pid)
		}
		return map[string]any{"pid": pid, "memory_kb": 0}
	}
	return nil
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

func (a *Agent) processFind(w http.ResponseWriter, r *http.Request, s *Server) {
	pids := []int{}
	if pid := a.sup.MainPID(s.Slug); pid > 0 && rustInfo(pid) != nil {
		pids = append(pids, pid)
	}
	writeJSON(w, 200, map[string]any{"pids": pids})
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
	main := a.sup.MainPID(s.Slug)
	if main != int(pid) {
		if rustInfo(int(pid)) != nil {
			fail(w, 409, "not_this_server", fmt.Sprintf("Process %d belongs to another server.", pid))
			return
		}
		writeJSON(w, 200, map[string]any{"killed": false})
		return
	}
	// No verified SIGTERM save in Rust: the panel saves over RCON first, then the unit is killed.
	if err := a.sup.Kill(s.Slug); err != nil {
		log.Printf("%s: kill of process %d failed: %v", s.Slug, pid, err)
		fail(w, 409, "not_this_server", upperFirst(err.Error())+".")
		return
	}
	log.Printf("%s: killed (process %d)", s.Slug, pid)
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
	if a.sup.MainPID(s.Slug) != int(pid) {
		if rustInfo(int(pid)) != nil {
			fail(w, 409, "refused", fmt.Sprintf("Process %d belongs to another server.", pid))
			return
		}
		writeJSON(w, 200, map[string]any{"applied": false})
		return
	}
	count := cores()
	coreList := make([]int, 0, len(list))
	for _, c := range list {
		if c < 0 || c >= int64(count) {
			fail(w, 409, "refused", fmt.Sprintf("This machine has no core %d.", c))
			return
		}
		coreList = append(coreList, int(c))
	}
	if err := a.sup.SetCPUs(s.Slug, coreList); err != nil {
		fail(w, 409, "refused", upperFirst(err.Error())+".")
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

// fileExists reports anything at p (also a link).
func fileExists(p string) bool { _, err := os.Lstat(p); return err == nil }
