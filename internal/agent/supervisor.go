package agent

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Supervisor runs each Rust server as its own systemd unit, rerust-server@<slug>.service (installed by install.sh):
// it runs as the game user, sees only its own folder, and the agent may only start/stop/kill these units (polkit
// rule from install.sh). So a game server's plugins can't reach the agent, its keys, or other servers.
type Supervisor interface {
	// Start starts the unit (its launcher reads .rerust/launch.json in the server folder) and returns the PID.
	Start(slug string) (int, error)
	// MainPID is the unit's running process, 0 when it isn't running.
	MainPID(slug string) int
	// Kill ends the server at once (SIGKILL to the whole unit) and waits until it is gone.
	Kill(slug string) error
	// SetCPUs pins the running unit to these cores ([] = all).
	SetCPUs(slug string, cores []int) error
}

// UnitName is the systemd unit of a server.
func UnitName(slug string) string { return "rerust-server@" + slug + ".service" }

type systemdSupervisor struct{}

func systemctl(args ...string) (string, error) {
	out, err := exec.Command("systemctl", append([]string{"--no-ask-password"}, args...)...).CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		if text == "" {
			text = err.Error()
		}
		return text, errors.New(text)
	}
	return text, nil
}

func (systemdSupervisor) props(slug string) (state string, pid int) {
	out, _ := systemctl("show", "--property=ActiveState,MainPID", UnitName(slug))
	for _, line := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(line, "ActiveState="); ok {
			state = v
		}
		if v, ok := strings.CutPrefix(line, "MainPID="); ok {
			pid, _ = strconv.Atoi(v)
		}
	}
	return state, pid
}

func (s systemdSupervisor) Start(slug string) (int, error) {
	_, _ = systemctl("reset-failed", UnitName(slug)) // a crashed run must not block this start
	if out, err := systemctl("start", UnitName(slug)); err != nil {
		return 0, fmt.Errorf("systemd could not start the server: %s", out)
	}
	// The launcher execs RustDedicated in place: wait until the unit's process is the game.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		state, pid := s.props(slug)
		if state == "failed" || state == "inactive" {
			return 0, fmt.Errorf("%s exited immediately after starting (check its log)", Executable)
		}
		if pid > 0 && procComm(pid) == commName {
			time.Sleep(500 * time.Millisecond)
			if st, p := s.props(slug); p == pid && st == "active" {
				return pid, nil
			}
			return 0, fmt.Errorf("%s exited immediately after starting (check its log)", Executable)
		}
		time.Sleep(200 * time.Millisecond)
	}
	return 0, errors.New("the server did not start within 10 seconds")
}

func (s systemdSupervisor) MainPID(slug string) int {
	state, pid := s.props(slug)
	if state != "active" && state != "deactivating" && state != "activating" {
		return 0
	}
	return pid
}

func (s systemdSupervisor) Kill(slug string) error {
	if _, err := systemctl("kill", "--signal=SIGKILL", UnitName(slug)); err != nil && s.MainPID(slug) > 0 {
		return fmt.Errorf("could not stop the server: %v", err)
	}
	for i := 0; i < 50 && s.MainPID(slug) > 0; i++ {
		time.Sleep(100 * time.Millisecond)
	}
	_, _ = systemctl("stop", UnitName(slug))
	_, _ = systemctl("reset-failed", UnitName(slug))
	return nil
}

func (s systemdSupervisor) SetCPUs(slug string, cores []int) error {
	parts := make([]string, 0, len(cores))
	for _, c := range cores {
		parts = append(parts, strconv.Itoa(c))
	}
	spec := strings.Join(parts, ",") // "" = every core again
	if out, err := systemctl("set-property", "--runtime", UnitName(slug), "AllowedCPUs="+spec); err != nil {
		return fmt.Errorf("could not set CPU affinity: %s", out)
	}
	return nil
}

// commName is RustDedicated as /proc/<pid>/comm shows it (cut to 15 characters by the kernel).
var commName = Executable[:min(len(Executable), 15)]

func procComm(pid int) string {
	raw, err := os.ReadFile(procRoot() + "/" + strconv.Itoa(pid) + "/comm")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}
