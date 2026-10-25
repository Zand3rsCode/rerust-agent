package agent

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Zand3rsCode/rerust-agent/internal/jail"
)

// AppID is Rust's dedicated server on Steam.
const AppID = "258550"

var percentLine = regexp.MustCompile(`^\s*(\d{1,3}(?:\.\d+)?)%`)

/* ---------- DepotDownloader ---------- */

// depotInstall downloads / updates / validates the game into the server folder.
func (a *Agent) depotInstall(s *Server, branch string, j *Job) error {
	if !branches[branch] {
		return errors.New("invalid branch")
	}
	depot := a.Cfg.DepotDownloader
	if !jail.IsFile(depot) {
		return fmt.Errorf("DepotDownloader not found at %s - set depotdownloader in the agent's config", depot)
	}
	if err := os.MkdirAll(s.Dir(), 0o755); err != nil {
		return fmt.Errorf("could not create %s", s.Dir())
	}
	args := []string{"-app", AppID, "-os", "linux", "-dir", s.Dir(), "-validate"}
	if branch != "main" {
		args = append(args, "-branch", branch) // Steam's name for it: "public" only for main
	}
	j.log("> DepotDownloader " + strings.Join(args, " "))

	cmd := exec.Command(depot, args...)
	cmd.Dir = filepath.Dir(depot)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("could not start DepotDownloader: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait(); pw.Close() }()

	lines := make(chan struct{})
	go func() {
		defer close(lines)
		sc := bufio.NewScanner(pr)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		sc.Split(scanLinesCR)
		for sc.Scan() {
			line := strings.TrimRight(sc.Text(), "\r")
			if line == "" {
				continue
			}
			j.log(line)
			if m := percentLine.FindStringSubmatch(line); m != nil {
				p, _ := strconv.ParseFloat(m[1], 64)
				j.progress(p)
			}
		}
	}()

	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var err error
wait:
	for {
		select {
		case err = <-done:
			break wait
		case <-tick.C:
			if j.cancelled() {
				j.log("Cancelling...")
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
					<-done
				}
				<-lines
				return errCancelled
			}
		}
	}
	<-lines
	if err != nil {
		code := -1
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			code = exit.ExitCode()
		}
		return fmt.Errorf("DepotDownloader exited with code %d", code)
	}
	// DepotDownloader doesn't always keep the executable bit.
	if info, err := os.Stat(s.Exe()); err == nil && info.Mode()&0o111 == 0 {
		_ = os.Chmod(s.Exe(), 0o755)
		j.log("Made " + Executable + " executable.")
	}
	return nil
}

// scanLinesCR splits on \n and on a lone \r (progress lines overwrite each other with \r).
func scanLinesCR(data []byte, atEOF bool) (int, []byte, error) {
	for i, c := range data {
		if c == '\n' || c == '\r' {
			return i + 1, data[:i], nil
		}
	}
	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}
	return 0, nil, nil
}

/* ---------- Oxide / Carbon ---------- */

// trustedHosts Oxide/Carbon may be downloaded from (with their CDNs), https only.
var trustedHosts = []string{"umod.org", "github.com", "githubusercontent.com"}

func assertTrustedURL(raw string) error {
	u, err := url.Parse(raw)
	if err == nil && u.Scheme == "https" {
		host := strings.ToLower(u.Hostname())
		for _, h := range trustedHosts {
			if host == h || strings.HasSuffix(host, "."+h) {
				return nil
			}
		}
	}
	return fmt.Errorf("refusing to download from %s: only https from %s (and their subdomains) is allowed", raw, strings.Join(trustedHosts, ", "))
}

func (s *Server) manifestPath() string { return s.LogDir() + "/mod-manifest.json" }

// modInstall downloads a framework and unpacks it over the server folder.
func (a *Agent) modInstall(s *Server, framework string, j *Job) ([]string, error) {
	if !frameworks[framework] {
		return nil, errors.New("unknown mod framework")
	}
	link := a.Cfg.Mods[framework]
	if err := assertTrustedURL(link); err != nil {
		return nil, err
	}
	dir := a.Cfg.StateDir + "/downloads"
	_ = os.MkdirAll(dir, 0o750)
	tmp := dir + "/" + framework + "-" + randomHex(4) + ".download"
	defer os.Remove(tmp)

	j.log("Downloading " + link)
	client := &http.Client{
		Timeout: 5 * time.Minute,
		// Every redirect must stay on https and on a known host (GitHub sends downloads to its CDN).
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			return assertTrustedURL(req.URL.String())
		},
	}
	resp, err := client.Get(link)
	if err != nil {
		return nil, fmt.Errorf("download failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("download failed with HTTP %d", resp.StatusCode)
	}
	out, err := os.Create(tmp)
	if err != nil {
		return nil, err
	}
	hash := sha256.New()
	size, err := io.Copy(io.MultiWriter(out, hash), io.LimitReader(resp.Body, 1<<30))
	out.Close()
	if err != nil {
		return nil, fmt.Errorf("download failed: %v", err)
	}
	// Logged so a changed download is visible in the task history.
	j.logf("Downloaded %.1f MB, SHA-256 %s", float64(size)/1048576, hex.EncodeToString(hash.Sum(nil)))
	j.log("Extracting into " + s.Dir())
	files, err := extractArchive(tmp, s.Dir(), MaxModBytes, MaxModEntries)
	if err != nil {
		return nil, err
	}
	j.logf("%d files extracted.", len(files))
	raw, _ := json.MarshalIndent(map[string]any{"framework": framework, "files": files}, "", "    ")
	_ = os.WriteFile(s.manifestPath(), raw, 0o640)
	return files, nil
}

var carbonUserData = regexp.MustCompile(`(?i)^carbon/(plugins|configs|data|lang|logs)/`)

// modRemove: Carbon's loader files go (user data is kept); Oxide replaced game files, so the game is validated.
func (a *Agent) modRemove(s *Server, framework, branch string, j *Job) error {
	if framework == "carbon" {
		var manifest struct {
			Framework string   `json:"framework"`
			Files     []string `json:"files"`
		}
		if raw, err := os.ReadFile(s.manifestPath()); err == nil {
			_ = json.Unmarshal(raw, &manifest)
		}
		files := []string{}
		if manifest.Framework == "carbon" {
			files = manifest.Files
		}
		files = append(files, "doorstop_config.ini", ".doorstop_version", "libdoorstop.so", "carbon.sh")
		removed := 0
		seen := map[string]bool{}
		for _, f := range files {
			rel, err := normaliseEntry(f)
			if err != nil || rel == "" || seen[rel] || carbonUserData.MatchString(rel) {
				continue
			}
			seen[rel] = true
			path := s.Dir() + "/" + rel
			if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() && os.Remove(path) == nil {
				removed++
			}
		}
		_ = os.Remove(s.manifestPath())
		j.logf("Removed %d Carbon files (plugins, configs and data were kept).", removed)
		return nil
	}
	j.log("Restoring vanilla game files (validate)...")
	if branch == "" {
		branch = "main"
	}
	if err := a.depotInstall(s, branch, j); err != nil {
		return err
	}
	_ = os.Remove(s.manifestPath())
	return nil
}

/* ---------- safe archives ---------- */

// Limits for framework archives (Oxide/Carbon unpack to well under 200 MB and ~2000 files).
const (
	MaxModEntries = 20000
	MaxModBytes   = 1 << 30
)

var winDevice = regexp.MustCompile(`(?i)^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$`)

// normaliseEntry checks an archive entry's name: never absolute, never "..", no odd names. "" = a folder entry.
func normaliseEntry(name string) (string, error) {
	name = strings.ReplaceAll(name, `\`, "/")
	if name == "" || strings.HasPrefix(name, "/") || regexp.MustCompile(`^[A-Za-z]:`).MatchString(name) || strings.ContainsRune(name, 0) {
		return "", fmt.Errorf("unsafe path in archive: %s", name)
	}
	var parts []string
	for _, part := range strings.Split(name, "/") {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			return "", fmt.Errorf("unsafe path in archive: %s", name)
		}
		if strings.Contains(part, ":") || winDevice.MatchString(part) {
			return "", fmt.Errorf("unsafe name in archive: %s", name)
		}
		parts = append(parts, part)
	}
	if strings.HasSuffix(name, "/") || len(parts) == 0 {
		return "", nil
	}
	return strings.Join(parts, "/"), nil
}

// extractArchive unpacks a .zip or .tar.gz into dest; everything is checked before anything is written.
func extractArchive(archive, dest string, maxBytes int64, maxEntries int) ([]string, error) {
	f, err := os.Open(archive)
	if err != nil {
		return nil, err
	}
	magic := make([]byte, 4)
	_, _ = io.ReadFull(f, magic)
	f.Close()
	switch {
	case string(magic) == "PK\x03\x04":
		return extractZip(archive, dest, nil, maxBytes, maxEntries)
	case magic[0] == 0x1f && magic[1] == 0x8b:
		return extractTarGz(archive, dest, maxBytes, maxEntries)
	}
	return nil, errors.New("unsupported archive format (expected .zip or .tar.gz)")
}

// writeInside writes one file under root, refusing to write through a link that leads out of it.
func writeInside(root, rel string, src io.Reader, mode os.FileMode) error {
	target := root + "/" + rel
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(target))
	realRoot, err2 := filepath.EvalSymlinks(root)
	if err != nil || err2 != nil || (parent != realRoot && !strings.HasPrefix(parent, realRoot+"/")) {
		return fmt.Errorf("refusing to write %s outside the destination folder", rel)
	}
	if jail.IsLink(target) {
		_ = os.Remove(target) // never write through a link
	}
	out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("could not write %s (is the server still running?)", target)
	}
	_, err = io.Copy(out, src)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	return err
}

func zipIsLink(f *zip.File) bool { return f.Mode()&os.ModeSymlink != 0 }

// extractZip unpacks every file whose name skip doesn't refuse; links refuse the whole archive.
func extractZip(archive, dest string, skip func(string) bool, maxBytes int64, maxEntries int) ([]string, error) {
	zr, err := zip.OpenReader(archive)
	if err != nil {
		return nil, errors.New("not a valid zip archive")
	}
	defer zr.Close()
	type entry struct {
		f   *zip.File
		rel string
	}
	var entries []entry
	var total int64
	for _, f := range zr.File {
		rel, err := normaliseEntry(f.Name)
		if err != nil {
			return nil, err
		}
		if rel == "" || (skip != nil && skip(rel)) {
			continue
		}
		if zipIsLink(f) {
			return nil, fmt.Errorf("archive contains a link: %s", rel)
		}
		entries = append(entries, entry{f, rel})
		total += int64(f.UncompressedSize64)
	}
	if len(entries) > maxEntries {
		return nil, fmt.Errorf("archive has too many files (%d)", len(entries))
	}
	if total > maxBytes {
		return nil, fmt.Errorf("archive unpacks to %.0f MB - more than the %d MB allowed", float64(total)/1048576, maxBytes/1048576)
	}
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return nil, err
	}
	written := []string{}
	var copied int64
	for _, e := range entries {
		rc, err := e.f.Open()
		if err != nil {
			return nil, fmt.Errorf("could not read %s from the archive", e.rel)
		}
		// The sizes in a zip can lie: never write more than the limit.
		lr := &io.LimitedReader{R: rc, N: maxBytes - copied + 1}
		err = writeInside(dest, e.rel, lr, 0o644)
		rc.Close()
		if err != nil {
			return nil, err
		}
		copied += (maxBytes - copied + 1) - lr.N
		if copied > maxBytes {
			return nil, errors.New("archive unpacks to more than allowed")
		}
		if e.f.Mode()&0o111 != 0 {
			_ = os.Chmod(dest+"/"+e.rel, 0o755)
		}
		written = append(written, e.rel)
	}
	return written, nil
}

// extractTarGz: only plain files and folders (no links, devices...), checked in a first pass.
func extractTarGz(archive, dest string, maxBytes int64, maxEntries int) ([]string, error) {
	open := func() (*tar.Reader, func(), error) {
		f, err := os.Open(archive)
		if err != nil {
			return nil, nil, err
		}
		gz, err := gzip.NewReader(f)
		if err != nil {
			f.Close()
			return nil, nil, errors.New("not a valid .tar.gz archive")
		}
		return tar.NewReader(gz), func() { gz.Close(); f.Close() }, nil
	}
	tr, closeFn, err := open()
	if err != nil {
		return nil, err
	}
	var count int
	var total int64
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			closeFn()
			return nil, errors.New("could not read the archive listing")
		}
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeDir {
			closeFn()
			return nil, fmt.Errorf("archive contains a link or special file: %s", h.Name)
		}
		if _, err := normaliseEntry(h.Name); err != nil {
			closeFn()
			return nil, err
		}
		count++
		total += h.Size
	}
	closeFn()
	if count > maxEntries {
		return nil, fmt.Errorf("archive has too many files (%d)", count)
	}
	if total > maxBytes {
		return nil, errors.New("archive unpacks to more than allowed")
	}
	tr, closeFn, err = open()
	if err != nil {
		return nil, err
	}
	defer closeFn()
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return nil, err
	}
	written := []string{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.New("could not read the archive")
		}
		rel, _ := normaliseEntry(h.Name)
		if rel == "" || h.Typeflag == tar.TypeDir {
			if rel != "" {
				_ = os.MkdirAll(dest+"/"+rel, 0o755)
			}
			continue
		}
		mode := os.FileMode(0o644)
		if h.FileInfo().Mode()&0o111 != 0 {
			mode = 0o755
		}
		if err := writeInside(dest, rel, io.LimitReader(tr, h.Size), mode); err != nil {
			return nil, err
		}
		written = append(written, rel)
	}
	return written, nil
}
