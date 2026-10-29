package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Zand3rsCode/rerust-agent/internal/config"
	"github.com/Zand3rsCode/rerust-agent/internal/jail"
)

// Job states (the panel's AgentJob constants).
const (
	Queued    = "queued"
	Running   = "running"
	Done      = "done"
	Failed    = "failed"
	Cancelled = "cancelled"
)

// KeepDays finished jobs (state + log) are kept.
const KeepDays = 14

var jobTypes = map[string]bool{"install": true, "mod_install": true, "mod_remove": true, "backup": true, "restore": true, "delete_folder": true}

// errCancelled ends a job as cancelled.
var errCancelled = errors.New("cancelled")

// errBusy: the server already has a job running.
type errBusy struct{ msg string }

func (e errBusy) Error() string { return e.msg }

// Job is one long piece of work. Its lines go to <id>.log; its state to <id>.json.
type Job struct {
	ID       int64          `json:"id"`
	Slug     string         `json:"slug"`
	Type     string         `json:"type"`
	Params   map[string]any `json:"params"`
	State    string         `json:"state"`
	Progress float64        `json:"progress"`
	Message  *string        `json:"message"`
	Result   any            `json:"result"`
	Started  int64          `json:"started_at,omitempty"`
	Finished int64          `json:"finished_at,omitempty"`
	cancel   bool
	lastSave time.Time
	m        *jobs
	logMu    sync.Mutex
}

func (j *Job) describe() map[string]any {
	j.m.mu.Lock()
	defer j.m.mu.Unlock()
	return map[string]any{"id": j.ID, "type": j.Type, "state": j.State, "progress": j.Progress, "message": j.Message, "result": j.Result}
}

func (j *Job) logPath() string { return fmt.Sprintf("%s/%d.log", j.m.dir, j.ID) }

// log appends one line to the job's log.
func (j *Job) log(line string) {
	j.logMu.Lock()
	defer j.logMu.Unlock()
	f, err := os.OpenFile(j.logPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.WriteString(strings.TrimRight(line, "\r\n") + "\n")
}

func (j *Job) logf(format string, args ...any) { j.log(fmt.Sprintf(format, args...)) }

// progress is saved at most every 2 s (DepotDownloader prints many percent lines).
func (j *Job) progress(percent float64) {
	j.m.mu.Lock()
	j.Progress = min(100, max(0, percent))
	save := time.Since(j.lastSave) >= 2*time.Second
	if save {
		j.lastSave = time.Now()
	}
	j.m.mu.Unlock()
	if save {
		j.m.save(j)
	}
}

func (j *Job) cancelled() bool {
	j.m.mu.Lock()
	defer j.m.mu.Unlock()
	return j.cancel
}

func (j *Job) finish(state string, message string, result any) {
	j.m.mu.Lock()
	j.State = state
	if message != "" {
		if len(message) > 1000 {
			message = message[:1000]
		}
		j.Message = &message
	}
	j.Result = result
	if state == Done {
		j.Progress = 100
	}
	j.Finished = time.Now().Unix()
	j.m.mu.Unlock()
	j.m.save(j)
}

type jobs struct {
	a    *Agent
	dir  string
	mu   sync.Mutex
	next int64
	all  map[int64]*Job
}

// openJobs loads the jobs; any that were active when the agent stopped are marked failed (their goroutine is gone).
func openJobs(a *Agent, dir string) (*jobs, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	m := &jobs{a: a, dir: dir, next: 1, all: map[int64]*Job{}}
	files, _ := filepath.Glob(dir + "/*.json")
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		j := &Job{m: m}
		if json.Unmarshal(raw, j) != nil || j.ID <= 0 {
			continue
		}
		if j.Finished > 0 && time.Since(time.Unix(j.Finished, 0)) > KeepDays*24*time.Hour {
			_ = os.Remove(f)
			_ = os.Remove(j.logPath())
			continue
		}
		if j.State == Queued || j.State == Running {
			j.log("ERROR: the job stopped unexpectedly (the agent was restarted).")
			msg := "The job stopped unexpectedly on the server's machine (the agent was restarted)."
			j.State, j.Message, j.Finished = Failed, &msg, time.Now().Unix()
			m.save(j)
		}
		m.all[j.ID] = j
		m.next = max(m.next, j.ID+1)
	}
	return m, nil
}

func (m *jobs) save(j *Job) {
	m.mu.Lock()
	raw, _ := json.Marshal(j)
	m.mu.Unlock()
	_ = config.WriteAtomic(fmt.Sprintf("%s/%d.json", m.dir, j.ID), raw, 0o640)
}

// busy is the server's active job, if any.
func (m *jobs) busy(slug string) *Job {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, j := range m.all {
		if j.Slug == slug && (j.State == Queued || j.State == Running) {
			return j
		}
	}
	return nil
}

// anyBusy is any server's active job (an install, backup, restore ...), if one runs.
func (m *jobs) anyBusy() *Job {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, j := range m.all {
		if j.State == Queued || j.State == Running {
			return j
		}
	}
	return nil
}

func (m *jobs) get(slug string, id int64) *Job {
	m.mu.Lock()
	defer m.mu.Unlock()
	if j, ok := m.all[id]; ok && j.Slug == slug {
		return j
	}
	return nil
}

// start creates a job and runs it in the background. One job per server at a time.
func (m *jobs) start(slug, kind string, params map[string]any) (*Job, error) {
	if !jobTypes[kind] {
		return nil, errors.New("unknown job type")
	}
	m.mu.Lock()
	// Checked and added under one lock: two requests at once can't both start a job for the same server.
	for _, other := range m.all {
		if other.Slug == slug && (other.State == Queued || other.State == Running) {
			m.mu.Unlock()
			return nil, errBusy{fmt.Sprintf("Another job (%s) is still running for %s.", other.Type, slug)}
		}
	}
	j := &Job{ID: m.next, Slug: slug, Type: kind, Params: params, State: Queued, m: m}
	m.next++
	m.all[j.ID] = j
	m.mu.Unlock()
	_ = os.WriteFile(j.logPath(), nil, 0o640)
	m.save(j)
	m.prune()
	if Inline {
		m.run(j)
	} else {
		go m.run(j)
	}
	return j, nil
}

// Inline runs jobs synchronously (tests).
var Inline = false

// beforePerform runs as a job starts its work (tests hold jobs there).
var beforePerform = func(*Job) {}

func (m *jobs) run(j *Job) {
	m.mu.Lock()
	if j.State != Queued {
		m.mu.Unlock()
		return
	}
	j.State, j.Started = Running, time.Now().Unix()
	m.mu.Unlock()
	m.save(j)
	defer func() {
		if r := recover(); r != nil {
			j.logf("ERROR: %v", r)
			j.finish(Failed, fmt.Sprint(r), nil)
		}
	}()
	beforePerform(j)
	result, err := m.perform(j)
	switch {
	case errors.Is(err, errCancelled):
		j.log("Cancelled.")
		j.finish(Cancelled, "Cancelled.", nil)
	case err != nil:
		j.log("ERROR: " + err.Error())
		j.finish(Failed, err.Error(), nil)
	default:
		j.finish(Done, "", result)
	}
}

func (m *jobs) perform(j *Job) (any, error) {
	a := m.a
	if j.Type == "delete_folder" {
		return nil, a.deleteFolder(j, fmt.Sprint(j.Params["path"]))
	}
	e, ok := a.servers.get(j.Slug)
	if !ok {
		return nil, fmt.Errorf("this node doesn't manage a server called %s", j.Slug)
	}
	s := a.server(j.Slug, e)
	str := func(k string) string { v, _ := j.Params[k].(string); return v }
	switch j.Type {
	case "install":
		branch := str("branch")
		if branch == "" {
			branch = "main"
		}
		if err := a.depotInstall(s, branch, j); err != nil {
			return nil, err
		}
		return map[string]any{"installed": s.Installed()}, nil
	case "mod_install":
		files, err := a.modInstall(s, str("framework"), j)
		if err != nil {
			return nil, err
		}
		return map[string]any{"files": len(files)}, nil
	case "mod_remove":
		return nil, a.modRemove(s, str("framework"), str("branch"), j)
	case "backup":
		name, size, err := a.backup(s, str("framework"), j.log)
		if err != nil {
			return nil, err
		}
		return map[string]any{"name": name, "size": size}, nil
	case "restore":
		code, _ := j.Params["code"].(bool)
		return a.restore(s, str("name"), code, j.log)
	}
	return nil, errors.New("unknown job type")
}

// deleteFolder deletes a removed server's folder - only ever inside <base>/_deleting.
func (a *Agent) deleteFolder(j *Job, path string) error {
	if !fileExists(path) {
		return nil
	}
	if !a.isTrashed(path) {
		return fmt.Errorf("refusing to delete %s: not inside %s", path, trashDir)
	}
	for _, wait := range []time.Duration{0, time.Minute, 5 * time.Minute} {
		if wait > 0 && !Inline {
			j.logf("Some files are still in use - trying again in %d s...", int(wait.Seconds()))
			time.Sleep(wait)
		}
		if jail.DeleteTree(path) {
			_ = os.Remove(filepath.Dir(path)) // the _deleting folder itself once nothing else waits in it
			j.log("Deleted " + path + ".")
			return nil
		}
	}
	return fmt.Errorf("some files in %s could not be deleted (in use?)", path)
}

func (m *jobs) prune() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, j := range m.all {
		if j.Finished > 0 && time.Since(time.Unix(j.Finished, 0)) > KeepDays*24*time.Hour {
			_ = os.Remove(fmt.Sprintf("%s/%d.json", m.dir, id))
			_ = os.Remove(j.logPath())
			delete(m.all, id)
		}
	}
}

/* ---------- handlers ---------- */

var branches = map[string]bool{"main": true, "staging": true}
var frameworks = map[string]bool{"oxide": true, "carbon": true}
var backupNameParam = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,80}$`)

func (a *Agent) jobStore(w http.ResponseWriter, r *http.Request, s *Server) {
	in, ok := parse(w, r)
	if !ok {
		return
	}
	kind := in.str("type")
	switch kind {
	case "install", "mod_install", "mod_remove", "backup", "restore":
	default:
		invalid(w, "The selected type is invalid.")
		return
	}
	p := in.object("params")
	params := map[string]any{}
	if v := p.str("branch"); p.has("branch") {
		if !branches[v] {
			invalid(w, "The selected params.branch is invalid.")
			return
		}
		params["branch"] = v
	}
	if p.has("framework") && p["framework"] != nil {
		v := p.str("framework")
		if !frameworks[v] {
			invalid(w, "The selected params.framework is invalid.")
			return
		}
		params["framework"] = v
	}
	if p.has("name") {
		v := p.str("name")
		if !backupNameParam.MatchString(v) {
			invalid(w, "The params.name field format is invalid.")
			return
		}
		params["name"] = v
	}
	if p.has("code") {
		v, ok := p.boolean("code")
		if !ok {
			invalid(w, "params.code must be true or false.")
			return
		}
		params["code"] = v
	}
	if (kind == "mod_install" || kind == "mod_remove") && params["framework"] == nil {
		invalid(w, "Which mod framework?")
		return
	}
	if kind == "restore" && params["name"] == nil {
		invalid(w, "Which backup?")
		return
	}
	j, err := a.jobs.start(s.Slug, kind, params)
	if err != nil {
		var busy errBusy
		if errors.As(err, &busy) {
			fail(w, 409, "busy", busy.msg)
			return
		}
		fail(w, 500, "failed", err.Error())
		return
	}
	writeJSON(w, 201, map[string]any{"job": j.describe()})
}

func (a *Agent) jobFrom(w http.ResponseWriter, r *http.Request, s *Server) *Job {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	j := a.jobs.get(s.Slug, id)
	if err != nil || j == nil {
		fail(w, 404, "unknown_job", "No such job on this node.")
		return nil
	}
	return j
}

// jobShow: state first, lines after - a finished job has written all its lines before its state changed.
func (a *Agent) jobShow(w http.ResponseWriter, r *http.Request, s *Server) {
	j := a.jobFrom(w, r, s)
	if j == nil {
		return
	}
	in, _ := readInput(r)
	offset, _ := in.integer("offset")
	reply := j.describe()
	t := tail(j.logPath(), max(0, offset), MaxChunk)
	reply["lines"], reply["offset"], reply["size"] = t["lines"], t["offset"], fileSize(j.logPath())
	writeJSON(w, 200, reply)
}

func (a *Agent) jobCancel(w http.ResponseWriter, r *http.Request, s *Server) {
	j := a.jobFrom(w, r, s)
	if j == nil {
		return
	}
	a.jobs.mu.Lock()
	queued := j.State == Queued
	if j.State == Queued || j.State == Running {
		j.cancel = true
	}
	a.jobs.mu.Unlock()
	if queued {
		j.finish(Cancelled, "Cancelled.", nil)
	}
	writeJSON(w, 200, map[string]any{"job": j.describe()})
}

// sortedKeys is a helper for stable output.
func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
