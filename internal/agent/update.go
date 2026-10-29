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
	"net/url"
	"os"
	"os/exec"
	"regexp"
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

// Asset is this machine's agent binary in a release.
func Asset() string { return "rerust-agent-linux-" + runtime.GOARCH }

var versionLine = regexp.MustCompile(`^# rerust-agent (\d+\.\d+\.\d+)$`)

// VerifyRelease checks SHA256SUMS against its signature and returns the version it names (its first line,
// "# rerust-agent x.y.z" - signed, so an old release can't be passed off under a newer tag).
func VerifyRelease(sums, sig []byte) (string, error) {
	block, _ := pem.Decode(releaseKey)
	if block == nil {
		return "", errors.New("no release key built in")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", err
	}
	pub, ok := key.(ed25519.PublicKey)
	if !ok || !ed25519.Verify(pub, sums, sig) {
		return "", errors.New("the release's signature is not valid - refusing to install it")
	}
	first, _, _ := strings.Cut(string(sums), "\n")
	m := versionLine.FindStringSubmatch(strings.TrimSpace(first))
	if m == nil {
		return "", errors.New("the signed SHA256SUMS names no version - refusing to install it")
	}
	return m[1], nil
}

// SumFor is the sha256 listed for name in SHA256SUMS ("<hex>  <name>" lines).
func SumFor(sums []byte, name string) (string, bool) {
	sc := bufio.NewScanner(strings.NewReader(string(sums)))
	found := ""
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name && len(f[0]) == 64 {
			if found != "" {
				return "", false // listed twice: refuse
			}
			found = strings.ToLower(f[0])
		}
	}
	return found, found != ""
}

// Newer: a > b for x.y.z versions (a leading v is ignored).
func Newer(a, b string) bool {
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

// releaseHosts the agent downloads releases from (https only; redirects must stay on them).
var releaseHosts = map[string]bool{"github.com": true, "objects.githubusercontent.com": true, "release-assets.githubusercontent.com": true}

// testHosts: tests may serve releases from these (never set outside tests).
var testHosts = map[string]bool{}

func allowedDownload(u *url.URL) bool {
	if testHosts[u.Host] {
		return true
	}
	return u.Scheme == "https" && u.User == nil && releaseHosts[strings.ToLower(u.Hostname())] && u.Port() == ""
}

var downloadClient = &http.Client{
	Timeout: 5 * time.Minute,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 || !allowedDownload(req.URL) {
			return errors.New("redirect to an address that is not GitHub's")
		}
		return nil
	},
}

func download(link string, limit int64) ([]byte, error) {
	u, err := url.Parse(link)
	if err != nil || !allowedDownload(u) {
		return nil, fmt.Errorf("refusing to download from %s", link)
	}
	resp, err := downloadClient.Get(link)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("download failed with HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err == nil && int64(len(data)) > limit {
		err = errors.New("the download is larger than expected")
	}
	return data, err
}

// UpdateDir is where the agent leaves a downloaded release for the root update step.
func UpdateDir(stateDir string) string { return stateDir + "/update" }

// UpdateStatusFile is written by the root update step (systemd RuntimeDirectory, readable by the agent). A variable
// only for tests.
var UpdateStatusFile = "/run/rerust-agent-update/status.json"

type updateRun struct {
	State   string `json:"state"` // downloading | installing | done | failed
	From    string `json:"from"`
	To      string `json:"to"`
	Message string `json:"message,omitempty"`
	At      int64  `json:"at"`
}

type updater struct {
	a    *Agent
	mu   sync.Mutex
	busy bool
	// API is GitHub's API (tests point it elsewhere).
	API string
	// Trigger starts the root update step (tests replace it).
	Trigger func() error
}

func newUpdater(a *Agent) *updater {
	return &updater{a: a, API: "https://api.github.com", Trigger: func() error {
		out, err := exec.Command("systemctl", "--no-ask-password", "start", "--no-block", "rerust-agent-update.service").CombinedOutput()
		if err != nil {
			return fmt.Errorf("could not start the update: %s", strings.TrimSpace(string(out)))
		}
		return nil
	}}
}

func (u *updater) statePath() string { return u.a.Cfg.StateDir + "/update.json" }

func (u *updater) save(run updateRun) {
	raw, _ := json.Marshal(run)
	_ = config.WriteAtomic(u.statePath(), raw, 0o600)
}

// settle (at start): the root step's own status lives in /run and is gone after a reboot, so an update that reached
// "installing" kept saying so for good. When this program is the version that update installed, it is done.
func (u *updater) settle() {
	raw, err := os.ReadFile(u.statePath())
	if err != nil {
		return
	}
	var run updateRun
	if json.Unmarshal(raw, &run) != nil || (run.State != "installing" && run.State != "downloading") {
		return
	}
	if run.To != "" && run.To == strings.TrimPrefix(u.a.Version, "v") {
		run.State, run.Message = "done", ""
		u.save(run)
	}
}

type release struct {
	Tag    string `json:"tag_name"`
	Assets []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

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

var errUpToDate = errors.New("up to date")

// startUpdate: download the newest release, check it, and hand it to the root update step. The agent can't replace
// its own program (it belongs to root) - so a game server can't either.
func (a *Agent) startUpdate(w http.ResponseWriter, r *http.Request) {
	u := a.update
	// The update restarts the agent, which ends every running job - a restore cut off mid-swap (SECURITY.md R7).
	if j := a.jobs.anyBusy(); j != nil {
		fail(w, 409, "busy", fmt.Sprintf("A %s is running for %s on this machine - update when it has finished.", j.Type, j.Slug))
		return
	}
	u.mu.Lock()
	if u.busy {
		u.mu.Unlock()
		fail(w, 409, "busy", "An update is already running on this machine.")
		return
	}
	u.busy = true
	u.mu.Unlock()
	rel, err := u.latest()
	if err == nil && !Newer(rel.Tag, a.Version) {
		err = errUpToDate
	}
	if err != nil {
		u.done()
		if errors.Is(err, errUpToDate) {
			fail(w, 409, "up_to_date", "This machine already runs the newest agent (v"+strings.TrimPrefix(a.Version, "v")+").")
			return
		}
		fail(w, 409, "cannot_update", err.Error())
		return
	}
	to := strings.TrimPrefix(rel.Tag, "v")
	run := updateRun{State: "downloading", From: a.Version, To: to, At: time.Now().Unix()}
	u.save(run)
	go u.fetch(rel, run)
	writeJSON(w, 200, map[string]any{"started": true, "from": a.Version, "to": to})
}

func (u *updater) done() {
	u.mu.Lock()
	u.busy = false
	u.mu.Unlock()
}

func (u *updater) fetch(rel *release, run updateRun) {
	defer u.done()
	finish := func(err error) {
		run.State, run.Message = "failed", err.Error()+" Nothing was changed."
		u.save(run)
	}
	links := map[string]string{}
	for _, a := range rel.Assets {
		links[a.Name] = a.URL
	}
	asset := Asset()
	if links[asset] == "" || links["SHA256SUMS"] == "" || links["SHA256SUMS.sig"] == "" {
		finish(fmt.Errorf("release %s has no %s, SHA256SUMS and SHA256SUMS.sig.", rel.Tag, asset))
		return
	}
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
	version, err := VerifyRelease(sums, sig)
	if err == nil && version != run.To {
		err = fmt.Errorf("the release is tagged v%s but its signed version is %s", run.To, version)
	}
	if err != nil {
		finish(err)
		return
	}
	want, ok := SumFor(sums, asset)
	if !ok {
		finish(errors.New("SHA256SUMS does not list " + asset + " once"))
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
	dir := UpdateDir(u.a.Cfg.StateDir)
	_ = os.MkdirAll(dir, 0o700)
	for name, data := range map[string][]byte{"SHA256SUMS": sums, "SHA256SUMS.sig": sig, asset: bin} {
		if err := config.WriteAtomic(dir+"/"+name, data, 0o600); err != nil {
			finish(err)
			return
		}
	}
	run.State = "installing"
	u.save(run)
	if err := u.Trigger(); err != nil {
		finish(err)
	}
}

func (a *Agent) updateStatus(w http.ResponseWriter, r *http.Request) {
	u := a.update
	var run map[string]any
	if raw, err := os.ReadFile(u.statePath()); err == nil {
		_ = json.Unmarshal(raw, &run)
	}
	// The root step's own answer, when it has run for this update.
	var root map[string]any
	if raw, err := os.ReadFile(UpdateStatusFile); err == nil && json.Unmarshal(raw, &root) == nil && run != nil {
		if at, _ := root["at"].(float64); int64(at) >= int64(toFloat(run["at"])) {
			run["state"], run["message"] = root["state"], root["message"]
		}
	}
	if run == nil {
		run = map[string]any{}
	}
	u.mu.Lock()
	run["busy"] = u.busy
	u.mu.Unlock()
	writeJSON(w, 200, map[string]any{"version": a.Version, "run": run, "lines": []string{}})
}

func toFloat(v any) float64 { f, _ := v.(float64); return f }
