package agent

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Zand3rsCode/rerust-agent/internal/jail"
)

// Map wipe: the map and everything tied to it; a blueprint wipe adds the blueprints. Only top-level files of the
// save folder are ever deleted - never folders (cfg/ holds bans and admins).
var (
	mapPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\.map$`),
		regexp.MustCompile(`(?i)\.sav$`),
		regexp.MustCompile(`(?i)\.sav\.\d+$`),
		regexp.MustCompile(`(?i)\.navmesh$`),
		regexp.MustCompile(`(?i)_occlusion_\d+\.dat$`),
		regexp.MustCompile(`(?i)^player\.states\.\d+\.db(-wal|-shm|-journal)?$`),
		regexp.MustCompile(`(?i)^sv\.files\.\d+\.db(-wal|-shm|-journal)?$`),
	}
	blueprintPatterns = []*regexp.Regexp{regexp.MustCompile(`(?i)^player\.blueprints\.\d+\.db(-wal|-shm|-journal)?$`)}
)

func (s *Server) filesToDelete(blueprints bool) ([]string, error) {
	dir := s.SaveDir()
	if !jail.IsDir(dir) {
		return []string{}, nil
	}
	real, err1 := filepath.EvalSymlinks(dir)
	root, err2 := filepath.EvalSymlinks(s.Dir())
	if err1 != nil || err2 != nil || !strings.HasPrefix(strings.ToLower(real), strings.ToLower(root+"/")) {
		return nil, errors.New("Save folder is outside the server directory - refusing to wipe.")
	}
	patterns := mapPatterns
	if blueprints {
		patterns = append(append([]*regexp.Regexp{}, mapPatterns...), blueprintPatterns...)
	}
	files := []string{}
	items, _ := os.ReadDir(real)
	for _, item := range items {
		info, err := os.Lstat(real + "/" + item.Name())
		if err != nil || !info.Mode().IsRegular() {
			continue // never folders, never links
		}
		for _, p := range patterns {
			if p.MatchString(item.Name()) {
				files = append(files, item.Name())
				break
			}
		}
	}
	sort.Strings(files)
	return files, nil
}

func (a *Agent) wipePreview(w http.ResponseWriter, r *http.Request, s *Server) {
	mapFiles, err := s.filesToDelete(false)
	if err != nil {
		fail(w, 409, "refused", err.Error())
		return
	}
	all, _ := s.filesToDelete(true)
	inMap := map[string]bool{}
	for _, f := range mapFiles {
		inMap[f] = true
	}
	extra := []string{}
	for _, f := range all {
		if !inMap[f] {
			extra = append(extra, f)
		}
	}
	writeJSON(w, 200, map[string]any{"map": mapFiles, "blueprints": extra})
}

func (a *Agent) wipe(w http.ResponseWriter, r *http.Request, s *Server) {
	in, ok := parse(w, r)
	if !ok {
		return
	}
	blueprints, okB := in.boolean("blueprints")
	if !okB || !in.has("blueprints") {
		invalid(w, "The blueprints field is required.")
		return
	}
	files, err := s.filesToDelete(blueprints)
	if err != nil {
		fail(w, 409, "refused", err.Error())
		return
	}
	deleted, failed := []string{}, []string{}
	for _, name := range files {
		if os.Remove(s.SaveDir()+"/"+name) == nil {
			deleted = append(deleted, name)
		} else {
			failed = append(failed, name)
		}
	}
	writeJSON(w, 200, map[string]any{"deleted": deleted, "failed": failed})
}

/* ---------- take over: what is in an existing folder (read-only) ---------- */

const (
	maxCfgBytes   = 65536
	maxIdentities = 20
)

func folderFramework(path string) string {
	if jail.IsDir(path+"/carbon/managed") && !jail.IsLink(path+"/carbon") {
		return "carbon"
	}
	if jail.IsFile(path+"/RustDedicated_Data/Managed/Oxide.Core.dll") || (jail.IsDir(path+"/oxide") && !jail.IsLink(path+"/oxide")) {
		return "oxide"
	}
	return "none"
}

func newestSave(dir string) any {
	var best map[string]any
	var bestTime int64
	files, _ := filepath.Glob(dir + "/*.sav")
	for _, f := range files {
		info, err := os.Lstat(f)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if best == nil || info.ModTime().Unix() > bestTime {
			name := filepath.Base(f)
			best = map[string]any{"file": name, "size": nil, "seed": nil, "mtime": info.ModTime().Unix()}
			if m := proceduralSave.FindStringSubmatch(name); m != nil {
				best["size"], best["seed"] = atoiOr(m[1]), atoiOr(m[2])
			}
			bestTime = info.ModTime().Unix()
		}
	}
	if best == nil {
		return nil
	}
	return best
}

func (a *Agent) folderInspect(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	path, ok := a.folderPath(slug)
	if !ok {
		fail(w, 404, "no_folder", "There is no folder "+slug+" on this machine.")
		return
	}
	exe := path + "/" + Executable
	var runningInfo any
	if jail.IsFile(exe) {
		pids := findByExecutable(exe)
		for _, pid := range pids {
			if argv := commandLine(pid); argv != nil {
				// Includes its RCON password: only ever returned to the authenticated panel (it needs it).
				runningInfo = map[string]any{"pid": pid, "args": argv[1:], "count": len(pids)}
				break
			}
		}
	}
	identities := []map[string]any{}
	serverDir := path + "/server"
	if jail.IsDir(serverDir) && !jail.IsLink(serverDir) {
		items, _ := os.ReadDir(serverDir)
		for _, item := range items {
			if len(identities) >= maxIdentities {
				break
			}
			sub := serverDir + "/" + item.Name()
			if !identityPattern.MatchString(item.Name()) || jail.IsLink(sub) || !jail.IsDir(sub) {
				continue
			}
			var cfg any
			cfgPath := sub + "/cfg/server.cfg"
			if !jail.IsLink(sub+"/cfg") && !jail.IsLink(cfgPath) && jail.IsFile(cfgPath) && fileSize(cfgPath) <= maxCfgBytes {
				if raw, err := os.ReadFile(cfgPath); err == nil {
					cfg = string(raw)
				}
			}
			identities = append(identities, map[string]any{"name": item.Name(), "cfg": cfg, "save": newestSave(sub)})
		}
	}
	writeJSON(w, 200, map[string]any{
		"slug":       slug,
		"path":       path,
		"installed":  jail.IsFile(exe),
		"framework":  folderFramework(path),
		"identities": identities,
		"running":    runningInfo,
		"last_start": lastStart(a.Cfg.StateDir, slug),
	})
}
