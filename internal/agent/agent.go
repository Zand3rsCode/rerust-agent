// Package agent is the ReRust agent API v1 (/agent/v1) - the same API and answers as the ReRust panel's PHP agent
// (its docs/NODES.md section 4.3), so the panel talks to both alike. Servers are addressed by slug only; the agent
// works out every path itself and never accepts one from a request.
package agent

import (
	"encoding/json"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Zand3rsCode/rerust-agent/internal/auth"
	"github.com/Zand3rsCode/rerust-agent/internal/config"
	"github.com/Zand3rsCode/rerust-agent/internal/sysstats"
)

// Protocol is bumped when the panel <-> agent API changes in a way the other side must know about.
const Protocol = 1

// MaxFailures wrong keys per IP in FailWindow, then 429.
const (
	MaxFailures = 20
	FailWindow  = 10 * time.Minute
)

var (
	slugPattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{1,31}$`)
	identityPattern = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)
)

// Agent serves the API.
type Agent struct {
	Version string
	Cfg     config.Config
	Auth    *auth.Store
	Stats   *sysstats.Sampler

	servers *registry
	jobs    *jobs
	update  *updater
	mux     *http.ServeMux

	failMu   sync.Mutex
	failures map[string][]time.Time
}

// New builds the agent (the state folder must exist).
func New(version string, cfg config.Config, store *auth.Store, stats *sysstats.Sampler) (*Agent, error) {
	a := &Agent{Version: version, Cfg: cfg, Auth: store, Stats: stats, failures: map[string][]time.Time{}}
	var err error
	if a.servers, err = openRegistry(cfg.StateDir + "/servers.json"); err != nil {
		return nil, err
	}
	if a.jobs, err = openJobs(a, cfg.StateDir+"/jobs"); err != nil {
		return nil, err
	}
	a.update = newUpdater(a)
	a.routes()
	return a, nil
}

// anyProtocol routes answer whatever the panel's protocol: an outdated machine must still be seen and updated.
var anyProtocol = map[string]bool{
	"GET /agent/v1/ping": true, "GET /agent/v1/metrics": true,
	"POST /agent/v1/update": true, "GET /agent/v1/update": true,
}

func (a *Agent) routes() {
	m := http.NewServeMux()
	h := func(pattern string, fn func(w http.ResponseWriter, r *http.Request)) { m.HandleFunc(pattern, fn) }
	s := func(pattern string, fn func(w http.ResponseWriter, r *http.Request, srv *Server)) {
		method, path, _ := strings.Cut(pattern, " ")
		m.HandleFunc(method+" /agent/v1/servers/{slug}"+path, func(w http.ResponseWriter, r *http.Request) {
			srv, ok := a.find(w, r.PathValue("slug"))
			if ok {
				fn(w, r, srv)
			}
		})
	}

	h("GET /agent/v1/ping", a.ping)
	h("GET /agent/v1/metrics", a.metrics)
	h("POST /agent/v1/update", a.startUpdate)
	h("GET /agent/v1/update", a.updateStatus)
	h("GET /agent/v1/folders", a.foldersList)
	h("GET /agent/v1/folders/{slug}", a.folderFree)
	h("GET /agent/v1/folders/{slug}/inspect", a.folderInspect)
	h("PUT /agent/v1/servers/{slug}", a.register)
	h("DELETE /agent/v1/servers/{slug}", a.destroy)
	s("GET ", func(w http.ResponseWriter, r *http.Request, srv *Server) { writeJSON(w, 200, a.describe(srv)) })

	s("POST /process/start", a.processStart)
	s("GET /process", a.processInfo)
	s("GET /process/find", a.processFind)
	s("POST /process/kill", a.processKill)
	s("POST /process/affinity", a.processAffinity)
	s("GET /log", a.logRead)
	s("GET /log/download", a.logDownload)
	s("PUT /files/write", a.fileWrite)
	s("GET /files/read", a.fileRead)
	s("GET /files/stat", a.fileStat)
	s("DELETE /files", a.fileDelete)
	s("POST /fm", a.fmOp)
	s("POST /fm/upload", a.fmUpload)
	s("GET /fm/download", a.fmDownload)
	s("POST /jobs", a.jobStore)
	s("GET /jobs/{id}", a.jobShow)
	s("POST /jobs/{id}/cancel", a.jobCancel)
	s("GET /wipe", a.wipePreview)
	s("POST /wipe", a.wipe)
	s("GET /maps", a.maps)
	s("GET /backups", a.backupsList)
	s("GET /backups/{name}", a.backupDownload)
	s("DELETE /backups/{name}", a.backupDelete)
	s("GET /backups/{name}/inspect", a.backupInspect)
	s("POST /backup-uploads", a.uploadBegin)
	s("PUT /backup-uploads/{id}", a.uploadChunk)
	s("POST /backup-uploads/{id}/finish", a.uploadFinish)
	s("DELETE /backup-uploads/{id}", a.uploadCancel)

	h("POST /agent/v1/pair", a.pair)
	a.mux = m
}

// ServeHTTP checks every request, then routes it. /rcon/... is the secure WebRCON pass-through.
func (a *Agent) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-ReRust-Agent", a.Version+"; protocol=1")
	ip := clientIP(r)
	loopback := ip == "127.0.0.1" || ip == "::1"

	if strings.HasPrefix(r.URL.Path, "/rcon/") {
		if !loopback && !a.ipAllowed(ip) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		a.rcon(w, r)
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/agent/v1/") {
		fail(w, 404, "not_found", "Unknown agent address.")
		return
	}
	if a.tooManyFailures(ip) {
		fail(w, 429, "too_many_attempts", "Too many wrong keys. Try again later.")
		return
	}
	if !loopback && !a.ipAllowed(ip) {
		fail(w, 403, "ip_not_allowed", "This address may not use the agent.")
		return
	}
	if r.TLS == nil && !loopback {
		fail(w, 403, "https_required", "The agent only answers over HTTPS.")
		return
	}
	_, pattern := a.mux.Handler(r)
	if pattern == "POST /agent/v1/pair" {
		a.mux.ServeHTTP(w, r)
		return
	}
	key, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !a.Auth.KeyOK(strings.TrimSpace(key)) {
		a.failed(ip)
		fail(w, 401, "bad_key", "Missing or wrong node key.")
		return
	}
	if pattern == "" {
		fail(w, 404, "not_found", "Unknown agent address.")
		return
	}
	if !anyProtocol[pattern] && r.Header.Get("X-ReRust-Protocol") != "1" {
		fail(w, 426, "protocol_mismatch", "Panel and node speak different agent protocols - update the older one.")
		return
	}
	a.mux.ServeHTTP(w, r)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		return ip.To4().String() // ::ffff:1.2.3.4 -> 1.2.3.4
	}
	return host
}

func (a *Agent) ipAllowed(ip string) bool {
	if len(a.Cfg.AllowedIPs) == 0 {
		return true
	}
	for _, allowed := range a.Cfg.AllowedIPs {
		if allowed == ip {
			return true
		}
		if _, network, err := net.ParseCIDR(allowed); err == nil && network.Contains(net.ParseIP(ip)) {
			return true
		}
	}
	return false
}

func (a *Agent) tooManyFailures(ip string) bool {
	a.failMu.Lock()
	defer a.failMu.Unlock()
	cut := time.Now().Add(-FailWindow)
	recent := a.failures[ip][:0]
	for _, t := range a.failures[ip] {
		if t.After(cut) {
			recent = append(recent, t)
		}
	}
	if len(recent) == 0 {
		delete(a.failures, ip)
	} else {
		a.failures[ip] = recent
	}
	return len(recent) >= MaxFailures
}

func (a *Agent) failed(ip string) {
	a.failMu.Lock()
	defer a.failMu.Unlock()
	a.failures[ip] = append(a.failures[ip], time.Now())
}

/* ---------- replies ---------- */

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// fail answers in the agent's error format {error, message}.
func fail(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": code, "message": message})
}

func invalid(w http.ResponseWriter, message string) { fail(w, 422, "invalid", message) }
