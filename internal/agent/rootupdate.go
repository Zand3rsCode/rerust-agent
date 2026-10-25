package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Zand3rsCode/rerust-agent/internal/config"
)

// InstallUpdate is the root update step (rerust-agent-update.service, oneshot, as root): it installs a release the
// agent downloaded into its update folder - but trusts nothing the agent says. It checks the signature itself with
// the key built into this (root-owned) program, requires a signed version newer than its own, checks the binary's
// sha256, writes the new program next to itself and restarts the agent. Files are opened without following links and
// size-limited; anything wrong = nothing changed.
func InstallUpdate(stateDir, selfVersion string) error {
	status := func(state, msg, to string) {
		raw, _ := json.Marshal(map[string]any{"state": state, "message": msg, "to": to, "at": time.Now().Unix()})
		_ = os.MkdirAll(filepath.Dir(UpdateStatusFile), 0o755)
		_ = config.WriteAtomic(UpdateStatusFile, raw, 0o644)
	}
	self, err := os.Executable()
	if err == nil {
		self, err = filepath.EvalSymlinks(self)
	}
	if err == nil {
		err = installUpdate(stateDir, selfVersion, self, status)
	}
	if err != nil {
		status("failed", err.Error()+" Nothing was changed.", "")
	}
	return err
}

func readNoFollow(path string, limit int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", filepath.Base(path), err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, fmt.Errorf("%s is not a plain file of at most %d bytes", filepath.Base(path), limit)
	}
	return io.ReadAll(io.LimitReader(f, limit))
}

// restartAgent restarts the agent after an update (tests replace it).
var restartAgent = func() ([]byte, error) {
	return exec.Command("systemctl", "restart", "rerust-agent.service").CombinedOutput()
}

// installUpdate replaces the program at self (the running root step's own file).
func installUpdate(stateDir, selfVersion, self string, status func(state, msg, to string)) error {
	dir := UpdateDir(stateDir)
	sums, err := readNoFollow(dir+"/SHA256SUMS", 1<<16)
	if err != nil {
		return err
	}
	sig, err := readNoFollow(dir+"/SHA256SUMS.sig", 1<<10)
	if err != nil {
		return err
	}
	version, err := VerifyRelease(sums, sig)
	if err != nil {
		return err
	}
	if !Newer(version, selfVersion) {
		return fmt.Errorf("v%s is not newer than the installed v%s", version, selfVersion)
	}
	want, ok := SumFor(sums, Asset())
	if !ok {
		return errors.New("SHA256SUMS does not list " + Asset() + " once")
	}
	bin, err := readNoFollow(dir+"/"+Asset(), 200<<20)
	if err != nil {
		return err
	}
	got := sha256.Sum256(bin)
	if hex.EncodeToString(got[:]) != want {
		return errors.New("the agent's checksum differs from the signed SHA256SUMS")
	}
	status("installing", "", version)
	tmp := self + ".new"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	_, werr := f.Write(bin)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(tmp)
		return werr
	}
	if out, err := exec.Command(tmp, "version").Output(); err != nil || string(out) != version+"\n" {
		_ = os.Remove(tmp)
		return fmt.Errorf("the new agent does not run or reports another version")
	}
	if err := os.Rename(tmp, self); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	for _, name := range []string{"SHA256SUMS", "SHA256SUMS.sig", Asset()} {
		_ = os.Remove(dir + "/" + name)
	}
	status("done", "Installed v"+version+" - the agent restarts (game servers keep running).", version)
	if out, err := restartAgent(); err != nil {
		return fmt.Errorf("installed v%s, but restarting the agent failed: %s", version, out)
	}
	return nil
}
