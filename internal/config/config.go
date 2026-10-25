// Package config reads the agent's settings (/etc/rerust-agent/config.json, written by install.sh).
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DefaultPath is where install.sh writes the config.
const DefaultPath = "/etc/rerust-agent/config.json"

// Config is the agent's settings. Secrets are not in here: the machine key's hash lives in the state folder
// (auth.json), the panel's RCON passwords never reach the disk.
type Config struct {
	// Listen is the HTTPS address, e.g. ":443".
	Listen string `json:"listen"`
	// BaseDir holds one folder per server (<base>/<slug>) plus _backups and _deleting.
	BaseDir string `json:"base_dir"`
	// StateDir holds the agent's own data: auth.json, the server registry, jobs, console logs, the certificate.
	StateDir string `json:"state_dir"`
	// DepotDownloader is the full path of the DepotDownloader binary.
	DepotDownloader string `json:"depotdownloader"`
	// AllowedIPs may call the agent (empty = any address; the key is always needed).
	AllowedIPs []string `json:"allowed_ips"`
	// UpdateRepo is the GitHub repository the agent updates itself from.
	UpdateRepo string `json:"update_repo"`
	// Mods are the Oxide / Carbon download links (https from trusted hosts only).
	Mods map[string]string `json:"mods"`
	// Domain (optional) is the machine's own name; with it the agent may get a Let's Encrypt certificate later.
	Domain string `json:"domain"`
}

// Defaults are the values install.sh uses.
func Defaults() Config {
	return Config{
		Listen:          ":443",
		BaseDir:         "/srv/rust",
		StateDir:        "/var/lib/rerust-agent",
		DepotDownloader: "/opt/depotdownloader/DepotDownloader",
		UpdateRepo:      "Zand3rsCode/rerust-agent",
		Mods: map[string]string{
			"oxide":  "https://github.com/OxideMod/Oxide.Rust/releases/latest/download/Oxide.Rust-linux.zip",
			"carbon": "https://github.com/CarbonCommunity/Carbon/releases/download/production_build/Carbon.Linux.Release.tar.gz",
		},
	}
}

// Load reads path over the defaults. A missing file = the defaults.
func Load(path string) (Config, error) {
	c := Defaults()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil
		}
		return c, err
	}
	mods := c.Mods
	if err := json.Unmarshal(data, &c); err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	for name, url := range mods {
		if c.Mods[name] == "" {
			c.Mods[name] = url
		}
	}
	c.BaseDir = strings.TrimRight(c.BaseDir, "/")
	c.StateDir = strings.TrimRight(c.StateDir, "/")
	if !filepath.IsAbs(c.BaseDir) || !filepath.IsAbs(c.StateDir) {
		return c, fmt.Errorf("%s: base_dir and state_dir must be absolute paths", path)
	}
	return c, nil
}

// Save writes the config (0640).
func Save(path string, c Config) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return WriteAtomic(path, append(data, '\n'), 0o640)
}

// WriteAtomic writes a file through a temporary file and a rename.
func WriteAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
