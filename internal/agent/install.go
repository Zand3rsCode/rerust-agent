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
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"os/exec"
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
	if err := a.readyForFiles(s); err != nil {
		return err
	}
	args := []string{"-app", AppID, "-os", "linux", "-dir", s.Dir(), "-validate"}
	if branch != "main" {
		args = append(args, "-branch", branch) // Steam's name for it: "public" only for main
	}
	j.log("> DepotDownloader " + strings.Join(args, " "))

	cmd := exec.Command(depot, args...)
	// Its own folder is root's (the agent can't replace it): it works in the agent's state folder.
	cmd.Dir = a.Cfg.StateDir + "/depotdownloader"
	if err := os.MkdirAll(cmd.Dir, 0o700); err != nil {
		return err
	}
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

// readyForFiles: game files are only installed into a stopped server (no game code running that could race the
// writes) whose folder holds no links - DepotDownloader writes by path, so a link left by a plugin could otherwise
// lead its writes into another server or the agent's own files.
func (a *Agent) readyForFiles(s *Server) error {
	if a.sup.MainPID(s.Slug) > 0 {
		return errors.New("the server is running - stop it first")
	}
	if err := s.ensureDir(); err != nil {
		return err
	}
	j, err := jail.Open(s.Dir())
	if err != nil {
		return err
	}
	defer j.Close()
	var links []string
	_ = fs.WalkDir(j.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if p == gameDir+"/home" && d.IsDir() {
			return fs.SkipDir // Steam's own links for the game's HOME (a link there is reported like any other)
		}
		if d.Type()&fs.ModeSymlink != 0 && len(links) < 10 {
			links = append(links, p)
		}
		return nil
	})
	if len(links) > 0 {
		return fmt.Errorf("the server folder contains links (%s) - remove them in the File Manager first", strings.Join(links, ", "))
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
func (a *Agent) modInstall(s *Server, framework string, job *Job) ([]string, error) {
	if !frameworks[framework] {
		return nil, errors.New("unknown mod framework")
	}
	if err := a.readyForFiles(s); err != nil {
		return nil, err
	}
	j := job
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
	sj, err := jail.Open(s.Dir())
	if err != nil {
		return nil, err
	}
	defer sj.Close()
	files, err := extractArchive(tmp, sj, MaxModBytes, MaxModEntries)
	if err != nil {
		return nil, err
	}
	j.logf("%d files extracted.", len(files))
	raw, _ := json.MarshalIndent(map[string]any{"framework": framework, "files": files}, "", "    ")
	_ = os.WriteFile(s.manifestPath(), raw, 0o600)
	return files, nil
}

var carbonUserData = regexp.MustCompile(`(?i)^carbon/(plugins|configs|data|lang|logs)/`)

// modRemove: Carbon's loader files go (user data is kept); Oxide replaced game files, so the game is validated.
func (a *Agent) modRemove(s *Server, framework, branch string, j *Job) error {
	if a.sup.MainPID(s.Slug) > 0 {
		return errors.New("the server is running - stop it first")
	}
	if framework == "carbon" {
		sj, err := jail.Open(s.Dir())
		if err != nil {
			return err
		}
		defer sj.Close()
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
			if sj.IsFile(rel) && sj.Remove(rel) == nil {
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

// extractArchive unpacks a .zip or .tar.gz into the jail; everything is checked before anything is written.
func extractArchive(archive string, j *jail.Jail, maxBytes int64, maxEntries int) ([]string, error) {
	f, err := os.Open(archive)
	if err != nil {
		return nil, err
	}
	magic := make([]byte, 4)
	_, _ = io.ReadFull(f, magic)
	f.Close()
	switch {
	case string(magic) == "PK\x03\x04":
		return extractZip(archive, j, "", nil, maxBytes, maxEntries)
	case magic[0] == 0x1f && magic[1] == 0x8b:
		return extractTarGz(archive, j, maxBytes, maxEntries)
	}
	return nil, errors.New("unsupported archive format (expected .zip or .tar.gz)")
}

// writeEntry writes one file into the jail: a new temporary file + rename (a link or hardlink at the target is
// replaced, never written through), mode set on the open file.
func writeEntry(j *jail.Jail, rel string, src io.Reader, limit int64, executable bool) error {
	if _, err := j.MkdirAll(parentOf(rel)); err != nil {
		return err
	}
	mode := fs.FileMode(0o660)
	if executable {
		mode = 0o770
	}
	if j.IsDir(rel) {
		return fmt.Errorf("%s is a folder in the destination", rel)
	}
	if err := j.WriteAtomicFrom(rel, src, limit, mode); err != nil {
		return fmt.Errorf("could not write %s (is the server still running?)", rel)
	}
	return nil
}

func zipIsLink(f *zip.File) bool { return f.Mode()&os.ModeSymlink != 0 }

// extractZip unpacks every file whose name skip doesn't refuse into prefix/ inside the jail; links refuse the
// whole archive.
func extractZip(archive string, j *jail.Jail, prefix string, skip func(string) bool, maxBytes int64, maxEntries int) ([]string, error) {
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
		if _, err := jail.Normalise(rel); err != nil {
			return nil, fmt.Errorf("unsafe name in archive: %s", rel)
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
	written := []string{}
	left := maxBytes
	for _, e := range entries {
		rc, err := e.f.Open()
		if err != nil {
			return nil, fmt.Errorf("could not read %s from the archive", e.rel)
		}
		// archive/zip refuses entries larger than their header says; the limit is the rest of the allowance.
		err = writeEntry(j, strings.Trim(prefix+"/"+e.rel, "/"), rc, left, e.f.Mode()&0o111 != 0)
		rc.Close()
		if err != nil {
			return nil, err
		}
		left -= int64(e.f.UncompressedSize64)
		written = append(written, e.rel)
	}
	return written, nil
}

// extractTarGz: only plain files and folders (no links, devices...), checked in a first pass.
func extractTarGz(archive string, j *jail.Jail, maxBytes int64, maxEntries int) ([]string, error) {
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
		rel, err := normaliseEntry(h.Name)
		if err == nil && rel != "" {
			_, err = jail.Normalise(rel)
		}
		if err != nil {
			closeFn()
			return nil, fmt.Errorf("unsafe name in archive: %s", h.Name)
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
		if rel == "" {
			continue
		}
		if h.Typeflag == tar.TypeDir {
			if _, err := j.MkdirAll(rel); err != nil {
				return nil, err
			}
			continue
		}
		if err := writeEntry(j, rel, io.LimitReader(tr, h.Size), h.Size, h.FileInfo().Mode()&0o111 != 0); err != nil {
			return nil, err
		}
		written = append(written, rel)
	}
	return written, nil
}
