package agent

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Zand3rsCode/rerust-agent/internal/config"
)

// releaseKey verifies SHA256SUMS of every release (Ed25519, signed by the owner with a key that never leaves their
// machine). The same key is in install.sh.
//
//go:embed release_key.pub.pem
var releaseKey []byte

// VerifySums checks SHA256SUMS against its signature.
func VerifySums(sums, sig []byte) error {
	block, _ := pem.Decode(releaseKey)
	if block == nil {
		return errors.New("no release key built in")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	pub, ok := key.(ed25519.PublicKey)
	if !ok || !ed25519.Verify(pub, sums, sig) {
		return errors.New("the release's signature is not valid - refusing to install it")
	}
	return nil
}

// SumFor is the sha256 listed for name in SHA256SUMS ("<hex>  <name>" lines).
func SumFor(sums []byte, name string) (string, bool) {
	sc := bufio.NewScanner(strings.NewReader(string(sums)))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name && len(f[0]) == 64 {
			return strings.ToLower(f[0]), true
		}
	}
	return "", false
}

// newer: a > b for x.y.z versions (a leading v is ignored).
func newer(a, b string) bool {
	pa, pb := versionParts(a), versionParts(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			return pa[i] > pb[i]
		}
	}
	return false
}

func versionParts(v string) [3]int {
	var out [3]int
	for i, p := range strings.SplitN(strings.TrimPrefix(v, "v"), ".", 3) {
		n, _ := strconv.Atoi(strings.SplitN(p, "-", 2)[0])
		out[i] = n
	}
	return out
}

type updateRun struct {
	State   string `json:"state"` // running | done | failed
	From    string `json:"from"`
	To      string `json:"to"`
	Message string `json:"message,omitempty"`
	At      int64  `json:"at"`
}

type updater struct {
	a    *Agent
	mu   sync.Mutex
	busy bool
	// Exit is called after the new binary is in place (systemd starts it again). Tests replace it.
	Exit func()
	// API is GitHub's API (tests point it elsewhere).
	API string
}

func newUpdater(a *Agent) *updater {
	return &updater{a: a, API: "https://api.github.com", Exit: func() { os.Exit(0) }}
}

func (u *updater) statePath() string { return u.a.Cfg.StateDir + "/update.json" }
func (u *updater) logPath() string   { return u.a.Cfg.StateDir + "/update.log" }

func (u *updater) save(run updateRun) {
	raw, _ := json.Marshal(run)
	_ = config.WriteAtomic(u.statePath(), raw, 0o640)
}

func (u *updater) log(line string) {
	f, err := os.OpenFile(u.logPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err == nil {
		fmt.Fprintf(f, "[%s] %s\n", time.Now().UTC().Format("2006-01-02 15:04:05"), line)
		f.Close()
	}
}

type release struct {
	Tag    string `json:"tag_name"`
	Assets []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

var httpClient = &http.Client{Timeout: 5 * time.Minute}

func (u *updater) latest() (*release, error) {
	req, _ := http.NewRequest("GET", u.API+"/repos/"+u.a.Cfg.UpdateRepo+"/releases/latest", nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("GitHub can't be reached: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GitHub answered %d for the latest release", resp.StatusCode)
	}
	var rel release
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&rel); err != nil {
		return nil, errors.New("GitHub's answer could not be read")
	}
	return &rel, nil
}

func download(link string, limit int64) ([]byte, error) {
	if !strings.HasPrefix(link, "https://github.com/") && !strings.HasPrefix(link, "https://objects.githubusercontent.com/") && !strings.HasPrefix(link, "http://127.0.0.1") {
		return nil, fmt.Errorf("refusing to download from %s", link)
	}
	resp, err := httpClient.Get(link)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("download failed with HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

// startUpdate: update this agent to the newest release (the panel may send its own version - ignored: the agent's
// versions are its own).
func (a *Agent) startUpdate(w http.ResponseWriter, r *http.Request) {
	u := a.update
	u.mu.Lock()
	if u.busy {
		u.mu.Unlock()
		fail(w, 409, "busy", "An update is already running on this machine.")
		return
	}
	u.busy = true
	u.mu.Unlock()
	rel, err := u.latest()
	if err == nil && !newer(rel.Tag, a.Version) {
		err = errUpToDate
	}
	if err != nil {
		u.mu.Lock()
		u.busy = false
		u.mu.Unlock()
		if errors.Is(err, errUpToDate) {
			fail(w, 409, "up_to_date", "This machine already runs the newest agent (v"+strings.TrimPrefix(a.Version, "v")+").")
			return
		}
		fail(w, 409, "cannot_update", err.Error())
		return
	}
	to := strings.TrimPrefix(rel.Tag, "v")
	run := updateRun{State: "running", From: a.Version, To: to, At: time.Now().Unix()}
	u.save(run)
	go u.install(rel, run)
	writeJSON(w, 200, map[string]any{"started": true, "from": a.Version, "to": to})
}

var errUpToDate = errors.New("up to date")

func (u *updater) install(rel *release, run updateRun) {
	finish := func(err error) {
		u.mu.Lock()
		u.busy = false
		u.mu.Unlock()
		if err != nil {
			u.log("ERROR: " + err.Error() + " Nothing was changed.")
			run.State, run.Message = "failed", err.Error()+" Nothing was changed."
		} else {
			run.State = "done"
		}
		u.save(run)
	}
	asset := "rerust-agent-linux-" + runtime.GOARCH
	links := map[string]string{}
	for _, a := range rel.Assets {
		links[a.Name] = a.URL
	}
	if links[asset] == "" || links["SHA256SUMS"] == "" || links["SHA256SUMS.sig"] == "" {
		finish(fmt.Errorf("release %s has no %s, SHA256SUMS and SHA256SUMS.sig", rel.Tag, asset))
		return
	}
	u.log("Updating from v" + run.From + " to v" + run.To + "...")
	sums, err := download(links["SHA256SUMS"], 1<<16)
	if err != nil {
		finish(err)
		return
	}
	sig, err := download(links["SHA256SUMS.sig"], 1<<10)
	if err != nil {
		finish(err)
		return
	}
	if err := VerifySums(sums, sig); err != nil {
		finish(err)
		return
	}
	want, ok := SumFor(sums, asset)
	if !ok {
		finish(errors.New("SHA256SUMS does not list " + asset))
		return
	}
	bin, err := download(links[asset], 200<<20)
	if err != nil {
		finish(err)
		return
	}
	got := sha256.Sum256(bin)
	if hex.EncodeToString(got[:]) != want {
		finish(errors.New("the downloaded agent's checksum differs"))
		return
	}
	self, err := os.Executable()
	if err == nil {
		self, err = filepath.EvalSymlinks(self)
	}
	if err != nil {
		finish(err)
		return
	}
	tmp := self + ".new"
	if err := os.WriteFile(tmp, bin, 0o755); err != nil {
		finish(fmt.Errorf("could not write %s: %v", tmp, err))
		return
	}
	if err := os.Rename(tmp, self); err != nil {
		_ = os.Remove(tmp)
		finish(fmt.Errorf("could not replace %s: %v", self, err))
		return
	}
	u.log("Installed v" + run.To + " - restarting the agent (game servers keep running).")
	finish(nil)
	time.Sleep(500 * time.Millisecond)
	u.Exit()
}

func (a *Agent) updateStatus(w http.ResponseWriter, r *http.Request) {
	u := a.update
	var run map[string]any
	if raw, err := os.ReadFile(u.statePath()); err == nil {
		_ = json.Unmarshal(raw, &run)
	}
	if run == nil {
		run = map[string]any{}
	}
	u.mu.Lock()
	run["busy"] = u.busy
	u.mu.Unlock()
	t := tail(u.logPath(), 0, 16384)
	lines, _ := t["lines"].([]string)
	if len(lines) > 30 {
		lines = lines[len(lines)-30:]
	}
	writeJSON(w, 200, map[string]any{"version": a.Version, "run": run, "lines": lines})
}
