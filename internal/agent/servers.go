package agent

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Zand3rsCode/rerust-agent/internal/config"
	"github.com/Zand3rsCode/rerust-agent/internal/jail"
)

// Executable is the game's binary name inside a server folder.
const Executable = "RustDedicated"

// Server is one registered server: its folder is always <base>/<slug>, its console logs <state>/servers/<slug>.
type Server struct {
	Slug     string `json:"slug"`
	Identity string `json:"identity"`
	base     string
	state    string
}

func (s *Server) Dir() string        { return s.base + "/" + s.Slug }
func (s *Server) Exe() string        { return s.Dir() + "/" + Executable }
func (s *Server) Installed() bool    { return jail.IsFile(s.Exe()) }
func (s *Server) LogPath() string    { return s.LogDir() + "/server.log" }
func (s *Server) OutputPath() string { return s.LogDir() + "/server.output.log" }

// SafeIdentity is the identity with anything but letters, digits, _ and - removed (the panel's safeIdentity).
func (s *Server) SafeIdentity() string {
	var b strings.Builder
	for _, r := range s.Identity {
		if r == '_' || r == '-' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "rerust"
	}
	return b.String()
}

// LogDir is created when missing.
func (s *Server) LogDir() string {
	dir := logDirFor(s.state, s.Slug)
	_ = os.MkdirAll(dir, 0o750)
	return dir
}

func logDirFor(state, slug string) string { return state + "/servers/" + slug }

// BackupDir is <base>/_backups/<slug>.
func (s *Server) BackupDir() string { return s.base + "/_backups/" + s.Slug }

// SaveDir is the identity's save folder.
func (s *Server) SaveDir() string { return s.Dir() + "/server/" + s.SafeIdentity() }

type registry struct {
	path string
	mu   sync.Mutex
	m    map[string]string // slug -> identity
}

func openRegistry(path string) (*registry, error) {
	r := &registry{path: path, m: map[string]string{}}
	raw, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(raw, &r.m); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return r, nil
}

func (r *registry) save() error {
	raw, _ := json.MarshalIndent(r.m, "", "  ")
	return config.WriteAtomic(r.path, raw, 0o640)
}

func (r *registry) get(slug string) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id, ok := r.m[slug]
	return id, ok
}

func (r *registry) set(slug, identity string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[slug] = identity
	return r.save()
}

func (r *registry) remove(slug string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.m, slug)
	return r.save()
}

func (r *registry) slugs() map[string]bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[string]bool{}
	for k := range r.m {
		out[k] = true
	}
	return out
}

func (a *Agent) server(slug, identity string) *Server {
	return &Server{Slug: slug, Identity: identity, base: a.Cfg.BaseDir, state: a.Cfg.StateDir}
}

// find is a registered server, or a 404 in the agent's format.
func (a *Agent) find(w http.ResponseWriter, slug string) (*Server, bool) {
	identity, ok := "", false
	if slugPattern.MatchString(slug) {
		identity, ok = a.servers.get(slug)
	}
	if !ok {
		fail(w, 404, "unknown_server", "This node doesn't manage a server called "+slug+".")
		return nil, false
	}
	return a.server(slug, identity), true
}

func (a *Agent) describe(s *Server) map[string]any {
	return map[string]any{
		"slug":       s.Slug,
		"identity":   s.Identity,
		"path":       s.Dir(),
		"exists":     jail.IsDir(s.Dir()),
		"installed":  s.Installed(),
		"depot":      jail.IsFile(a.Cfg.DepotDownloader),
		"depot_path": a.Cfg.DepotDownloader,
	}
}

/* ---------- machine ---------- */

func cores() int {
	n := 0
	raw, _ := os.ReadFile("/proc/stat")
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && strings.HasPrefix(f[0], "cpu") && f[0] != "cpu" {
			n++
		}
	}
	if n == 0 {
		n = runtime.NumCPU()
	}
	return n
}

func (a *Agent) ping(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"version":  a.Version,
		"protocol": Protocol,
		"role":     "agent",
		"agent":    "go",
		"os":       "linux",
		"cores":    cores(),
		"base_dir": a.Cfg.BaseDir,
		"time":     time.Now().Unix(),
	})
}

func (a *Agent) metrics(w http.ResponseWriter, r *http.Request) {
	snapshot := a.Stats.Latest()
	var snap any
	if snapshot != nil {
		snap = snapshot
	}
	writeJSON(w, 200, map[string]any{
		"version":  a.Version,
		"protocol": Protocol,
		"base_dir": a.Cfg.BaseDir,
		"fresh":    a.Stats.Fresh(),
		"snapshot": snap,
		"history":  a.Stats.History(),
	})
}

/* ---------- registry ---------- */

func (a *Agent) register(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	if !slugPattern.MatchString(slug) {
		fail(w, 404, "not_found", "Unknown agent address.")
		return
	}
	in, ok := parse(w, r)
	if !ok {
		return
	}
	identity := in.str("identity")
	if !identityPattern.MatchString(identity) {
		invalid(w, "The identity field format is invalid.")
		return
	}
	if err := a.servers.set(slug, identity); err != nil {
		fail(w, 500, "failed", err.Error())
		return
	}
	writeJSON(w, 200, a.describe(a.server(slug, identity)))
}

// destroy removes a server from this node: its folder is moved into <base>/_deleting at once (fails cleanly when a
// file is in use), then deleted by a job; the agent's logs for it go too. Backups are kept.
func (a *Agent) destroy(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	if !slugPattern.MatchString(slug) {
		fail(w, 404, "not_found", "Unknown agent address.")
		return
	}
	identity, _ := a.servers.get(slug)
	if identity == "" {
		identity = slug
	}
	srv := a.server(slug, identity)
	if a.jobs.busy(slug) != nil {
		fail(w, 409, "busy", "A job is still running for this server on its machine.")
		return
	}
	trashed, err := a.moveToTrash(srv)
	if err != nil {
		fail(w, 409, "in_use", err.Error())
		return
	}
	jail.DeleteTree(logDirFor(a.Cfg.StateDir, slug))
	_ = a.servers.remove(slug)
	var job any
	if trashed != "" {
		j, err := a.jobs.start(slug, "delete_folder", map[string]any{"path": trashed})
		if err == nil {
			job = j.describe()
		}
	}
	writeJSON(w, 200, map[string]any{"trashed": trashed != "", "job": job})
}

const trashDir = "_deleting"

// moveToTrash renames exactly <base>/<slug> (never a link, never anything else) into <base>/_deleting.
func (a *Agent) moveToTrash(s *Server) (string, error) {
	path := s.Dir()
	if _, err := os.Lstat(path); err != nil {
		return "", nil // never installed
	}
	base, err := filepath.EvalSymlinks(a.Cfg.BaseDir)
	if err != nil || jail.IsLink(path) || !jail.IsDir(path) {
		return "", fmt.Errorf("the files in %s were not deleted: it is not a normal folder inside the servers folder", path)
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil || filepath.Dir(real) != base || filepath.Base(real) != s.Slug {
		return "", fmt.Errorf("the files in %s were not deleted: the folder is not %s/%s", path, base, s.Slug)
	}
	trash := base + "/" + trashDir
	if err := os.MkdirAll(trash, 0o750); err != nil {
		return "", fmt.Errorf("could not create %s", trash)
	}
	target := fmt.Sprintf("%s/%s-%s-%s", trash, s.Slug, time.Now().Format("20060102-150405"), randomHex(3))
	if err := os.Rename(real, target); err != nil {
		return "", fmt.Errorf("could not delete %s: a file in it is still in use. Nothing was removed", real)
	}
	return target, nil
}

// isTrashed: a folder directly inside <base>/_deleting (and not a link).
func (a *Agent) isTrashed(path string) bool {
	base, err := filepath.EvalSymlinks(a.Cfg.BaseDir)
	if err != nil || jail.IsLink(path) || !jail.IsDir(path) {
		return false
	}
	real, err := filepath.EvalSymlinks(path)
	return err == nil && filepath.Dir(real) == base+"/"+trashDir
}

/* ---------- folders (Add server: free name, take over an existing folder) ---------- */

func (a *Agent) folderPath(slug string) (string, bool) {
	if !slugPattern.MatchString(slug) {
		return "", false
	}
	path := a.Cfg.BaseDir + "/" + slug
	if jail.IsLink(path) || !jail.IsDir(path) {
		return "", false
	}
	real, err1 := filepath.EvalSymlinks(path)
	base, err2 := filepath.EvalSymlinks(a.Cfg.BaseDir)
	return path, err1 == nil && err2 == nil && real == base+"/"+slug
}

func (a *Agent) folderFree(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	if !slugPattern.MatchString(slug) {
		fail(w, 404, "not_found", "Unknown agent address.")
		return
	}
	path := a.Cfg.BaseDir + "/" + slug
	_, err := os.Lstat(path)
	exists := err == nil
	empty := !exists
	if exists && jail.IsDir(path) && !jail.IsLink(path) {
		entries, _ := os.ReadDir(path)
		empty = len(entries) == 0
	}
	writeJSON(w, 200, map[string]any{"path": path, "exists": exists, "empty": empty})
}

func (a *Agent) foldersList(w http.ResponseWriter, r *http.Request) {
	registered := a.servers.slugs()
	out := []map[string]any{}
	entries, _ := os.ReadDir(a.Cfg.BaseDir)
	for _, e := range entries {
		path, ok := a.folderPath(e.Name())
		if !ok {
			continue
		}
		var mtime int64
		if info, err := os.Stat(path); err == nil {
			mtime = info.ModTime().Unix()
		}
		out = append(out, map[string]any{
			"slug":       e.Name(),
			"installed":  jail.IsFile(path + "/" + Executable),
			"registered": registered[e.Name()],
			"mtime":      mtime,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["slug"].(string) < out[j]["slug"].(string) })
	writeJSON(w, 200, map[string]any{"base": a.Cfg.BaseDir, "folders": out})
}
