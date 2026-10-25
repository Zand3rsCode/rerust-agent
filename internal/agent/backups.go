package agent

import (
	"archive/zip"
	"compress/flate"
	"crypto/sha256"
	"crypto/subtle"
	"encoding"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/Zand3rsCode/rerust-agent/internal/config"
	"github.com/Zand3rsCode/rerust-agent/internal/jail"
)

// FrameworkFolders go into a backup with the save folder and HarmonyFolders (the panel's Wiper::FRAMEWORK_FOLDERS).
var FrameworkFolders = map[string][]string{
	"carbon": {"carbon/plugins", "carbon/plugins-disabled", "carbon/data", "carbon/configs", "carbon/lang", "carbon/logs"},
	"oxide":  {"oxide/plugins", "oxide/plugins-disabled", "oxide/data", "oxide/config", "oxide/lang", "oxide/logs"},
}

// HarmonyFolders: the Harmony mods (code) and their own settings/data (the panel's Wiper::HARMONY_FOLDERS).
var HarmonyFolders = []string{"HarmonyMods", "HarmonyMods_Data"}

// backupSkip: caches Rust rebuilds on every start (the navmesh alone is ~100 MB per world).
var backupSkip = []*regexp.Regexp{regexp.MustCompile(`(?i)\.navmesh$`), regexp.MustCompile(`(?i)_occlusion_\d+\.dat$`)}

func skippedCache(name string) bool {
	for _, p := range backupSkip {
		if p.MatchString(name) {
			return true
		}
	}
	return false
}

func (s *Server) isBackupName(name string) bool {
	return regexp.MustCompile(`^` + regexp.QuoteMeta(s.Slug) + `-\d{8}-\d{6}\.zip$`).MatchString(name)
}

/* ---------- make a backup ---------- */

// backup zips the save folder (minus caches), the framework's folders, HarmonyMods and HarmonyMods_Data into <base>/_backups/<slug>.
// The server folder is read through the jail (os.Root): a link or a swapped folder can't pull other files in.
func (a *Agent) backup(s *Server, framework string, log func(string)) (string, int64, error) {
	target := s.BackupDir()
	if err := os.MkdirAll(target, 0o700); err != nil {
		return "", 0, fmt.Errorf("could not create backup folder %s", target)
	}
	j, err := jail.Open(s.Dir())
	if err != nil {
		return "", 0, err
	}
	defer j.Close()
	sources := []string{"server/" + s.SafeIdentity()}
	sources = append(sources, FrameworkFolders[framework]...)
	sources = append(sources, HarmonyFolders...)
	name := s.Slug + "-" + time.Now().Format("20060102-150405") + ".zip"
	file := target + "/" + name
	out, err := os.OpenFile(file, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", 0, fmt.Errorf("could not create %s", file)
	}
	zw := zip.NewWriter(out)
	zw.RegisterCompressor(zip.Deflate, func(w io.Writer) (io.WriteCloser, error) { return flate.NewWriter(w, 1) }) // fast; saves are large
	count, skipped, saves := 0, 0, 0
	var skippedBytes int64
	fsys := j.FS()
	var walkErr error
	for _, src := range sources {
		if !j.IsDir(src) {
			continue // missing, or a link: never followed
		}
		walkErr = fs.WalkDir(fsys, src, func(p string, d fs.DirEntry, err error) error {
			if err != nil || !d.Type().IsRegular() {
				return nil // links and special files are skipped; folders are walked
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			if skippedCache(d.Name()) {
				skipped++
				skippedBytes += info.Size()
				return nil
			}
			f, _, err := j.OpenRegular(p, -1)
			if err != nil {
				return nil // vanished or swapped meanwhile
			}
			defer f.Close()
			h, _ := zip.FileInfoHeader(info)
			h.Name, h.Method = p, zip.Deflate
			w, err := zw.CreateHeader(h)
			if err != nil {
				return err
			}
			if _, err := io.Copy(w, f); err != nil {
				return err
			}
			count++
			if strings.HasSuffix(strings.ToLower(d.Name()), ".sav") {
				saves++
			}
			return nil
		})
		if walkErr != nil {
			break
		}
	}
	if err := zw.Close(); walkErr == nil {
		walkErr = err
	}
	if err := out.Close(); walkErr == nil {
		walkErr = err
	}
	if walkErr != nil {
		_ = os.Remove(file)
		return "", 0, errors.New("writing the backup failed (disk full?)")
	}
	if saves == 0 {
		log("WARNING: the save folder has no world save (.sav) - this backup holds no world (e.g. a freshly wiped server).")
	}
	size := fileSize(file)
	extra := ""
	if skipped > 0 {
		extra = fmt.Sprintf(" (skipped %d cache file(s), %.0f MB: navmesh/occlusion - rebuilt by Rust)", skipped, float64(skippedBytes)/1048576)
	}
	log(fmt.Sprintf("Backup: %d files, %.1f MB%s -> %s", count, float64(size)/1048576, extra, file))
	return name, size, nil
}

/* ---------- list / download / delete ---------- */

func (a *Agent) backupsList(w http.ResponseWriter, r *http.Request, s *Server) {
	out := []map[string]any{}
	items, _ := os.ReadDir(s.BackupDir())
	for _, item := range items {
		if !s.isBackupName(item.Name()) {
			continue
		}
		info, err := os.Lstat(s.BackupDir() + "/" + item.Name())
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		out = append(out, map[string]any{"name": item.Name(), "size": info.Size(), "mtime": info.ModTime().Unix()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["name"].(string) > out[j]["name"].(string) }) // names hold the time
	writeJSON(w, 200, map[string]any{"backups": out})
}

func (a *Agent) backupPath(w http.ResponseWriter, r *http.Request, s *Server) (string, bool) {
	name := r.PathValue("name")
	if !s.isBackupName(name) {
		fail(w, 404, "not_found", "Not a backup of this server.")
		return "", false
	}
	return s.BackupDir() + "/" + name, true
}

func (a *Agent) backupDownload(w http.ResponseWriter, r *http.Request, s *Server) {
	path, ok := a.backupPath(w, r, s)
	if !ok {
		return
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		fail(w, 404, "not_found", "The backup file is missing.")
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		fail(w, 404, "not_found", "The backup file is missing.")
		return
	}
	sendFile(w, f, info.Size(), filepath.Base(path), "application/zip")
}

func (a *Agent) backupDelete(w http.ResponseWriter, r *http.Request, s *Server) {
	path, ok := a.backupPath(w, r, s)
	if !ok {
		return
	}
	info, err := os.Lstat(path)
	writeJSON(w, 200, map[string]any{"deleted": err == nil && info.Mode().IsRegular() && os.Remove(path) == nil})
}

/* ---------- inspect / restore ---------- */

// Restore limits; FreeMargin must stay free after unpacking or uploading.
const (
	RestoreMaxEntries = 100000
	RestoreMaxBytes   = 50 << 30
	FreeMargin        = 2 << 30
	ListSkipped       = 20
	stagingPrefix     = ".restore-"
)

var serverRoot = regexp.MustCompile(`^server/([A-Za-z0-9_\-]{1,64})/.`)
var proceduralSave = regexp.MustCompile(`^proceduralmap\.(\d{3,5})\.(\d{1,10})\.\d+\.sav$`)

// rootOf is the folder a backup entry belongs to, or "" when a restore never puts it back.
func rootOf(rel string) string {
	if m := serverRoot.FindStringSubmatch(rel); m != nil {
		return "server/" + m[1]
	}
	return codeRootOf(rel)
}

// isCodeRoot: plugins and HarmonyMods - restoring them runs their code on the next start, so only on request
// (HarmonyMods_Data is the mods' settings/data: restored always).
func isCodeRoot(root string) bool {
	return root == "HarmonyMods" || strings.HasSuffix(root, "/plugins") || strings.HasSuffix(root, "/plugins-disabled")
}

// codeRootOf is the framework folder (or a Harmony folder) an entry is in.
func codeRootOf(rel string) string {
	for _, list := range [][]string{FrameworkFolders["carbon"], FrameworkFolders["oxide"], HarmonyFolders} {
		for _, root := range list {
			if strings.HasPrefix(rel, root+"/") {
				return root
			}
		}
	}
	return ""
}

type backupInfo struct {
	Name         string         `json:"name"`
	Files        int            `json:"files"`
	Bytes        int64          `json:"bytes"`
	Identity     *string        `json:"identity"`
	Roots        []string       `json:"roots"`
	Skipped      []string       `json:"skipped"`
	SkippedCount int            `json:"skipped_count"`
	Map          map[string]any `json:"map"`
}

// inspectBackup is what a restore would put back; anything unsafe refuses the whole zip.
func inspectBackup(path, name string) (*backupInfo, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, errors.New("the backup is not a readable zip file")
	}
	defer zr.Close()
	if len(zr.File) > RestoreMaxEntries {
		return nil, fmt.Errorf("the backup has too many files (%d)", len(zr.File))
	}
	info := &backupInfo{Name: name, Roots: []string{}, Skipped: []string{}}
	roots, identities := map[string]bool{}, map[string]bool{}
	var save string
	var saveTime time.Time
	for _, f := range zr.File {
		rel, err := normaliseEntry(f.Name)
		if err != nil {
			return nil, err
		}
		if rel == "" {
			continue
		}
		if zipIsLink(f) {
			return nil, fmt.Errorf("the backup contains a link (%s) - refused", rel)
		}
		root := rootOf(rel)
		if root == "" {
			info.SkippedCount++
			if len(info.Skipped) < ListSkipped {
				info.Skipped = append(info.Skipped, rel)
			}
			continue
		}
		info.Files++
		info.Bytes += int64(f.UncompressedSize64)
		roots[root] = true
		if strings.HasPrefix(root, "server/") {
			identities[root] = true
			// The world: the newest .sav directly in the save folder (older copies are .sav.1, .sav.2).
			if strings.Count(rel, "/") == 2 && strings.HasSuffix(strings.ToLower(rel), ".sav") && (save == "" || f.Modified.After(saveTime)) {
				save, saveTime = filepath.Base(rel), f.Modified
			}
		}
	}
	if len(identities) > 1 {
		return nil, fmt.Errorf("the backup holds more than one save folder (%s) - refused", strings.Join(sortedKeys(identities), ", "))
	}
	if info.Bytes > RestoreMaxBytes {
		return nil, fmt.Errorf("the backup unpacks to %.1f GB - more than allowed", float64(info.Bytes)/(1<<30))
	}
	for id := range identities {
		v := strings.TrimPrefix(id, "server/")
		info.Identity = &v
	}
	if save != "" {
		info.Map = map[string]any{"file": save, "size": nil, "seed": nil}
		if m := proceduralSave.FindStringSubmatch(save); m != nil {
			info.Map["size"], info.Map["seed"] = atoiOr(m[1]), atoiOr(m[2])
		}
	}
	info.Roots = sortedKeys(roots)
	return info, nil
}

func atoiOr(s string) int64 {
	var n int64
	fmt.Sscan(s, &n)
	return n
}

func (a *Agent) backupInspect(w http.ResponseWriter, r *http.Request, s *Server) {
	path, ok := a.backupPath(w, r, s)
	if !ok {
		return
	}
	if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() {
		fail(w, 422, "refused", "No such backup of this server on this machine.")
		return
	}
	info, err := inspectBackup(path, r.PathValue("name"))
	if err != nil {
		fail(w, 422, "refused", upperFirst(err.Error())+".")
		return
	}
	writeJSON(w, 200, info)
}

func freeBytes(path string) (int64, bool) {
	var st syscall.Statfs_t
	if syscall.Statfs(path, &st) != nil {
		return 0, false
	}
	return int64(st.Bavail) * int64(st.Bsize), true
}

// restore puts a backup back into the (stopped) server: everything is unpacked into a staging folder inside the
// server folder, then each folder is swapped in whole by rename; on an error the old ones are put back. Plugins and
// HarmonyMods (code that runs on the next start) only with code = true. All through the jail.
func (a *Agent) restore(s *Server, name string, code bool, log func(string)) (any, error) {
	if a.sup.MainPID(s.Slug) > 0 {
		return nil, errors.New("the server is running - stop it before restoring a backup")
	}
	path := s.BackupDir() + "/" + name
	if st, err := os.Lstat(path); !s.isBackupName(name) || err != nil || !st.Mode().IsRegular() {
		return nil, errors.New("no such backup of this server on this machine")
	}
	info, err := inspectBackup(path, name)
	if err != nil {
		return nil, err
	}
	roots := []string{}
	leftOut := []string{}
	for _, root := range info.Roots {
		if !isCodeRoot(root) || code {
			roots = append(roots, root)
		} else {
			leftOut = append(leftOut, root)
		}
	}
	if len(roots) == 0 {
		return nil, errors.New("the backup holds nothing that can be restored without its plugins (ask for plugins and HarmonyMods too)")
	}
	j, err := jail.Open(s.Dir())
	if err != nil {
		return nil, fmt.Errorf("the server folder %s is missing", s.Dir())
	}
	defer j.Close()
	if free, ok := freeBytes(s.Dir()); ok && free < info.Bytes+FreeMargin {
		return nil, fmt.Errorf("not enough free disk space: the backup unpacks to %.1f GB", float64(info.Bytes)/(1<<30))
	}
	log(fmt.Sprintf("Restoring %s: %d files, %.1f MB (%s).", name, info.Files, float64(info.Bytes)/1048576, strings.Join(roots, ", ")))
	if len(leftOut) > 0 {
		log("Not restored (plugins / HarmonyMods run code - restore them only when asked): " + strings.Join(leftOut, ", "))
	}
	if info.SkippedCount > 0 {
		more := ""
		if info.SkippedCount > len(info.Skipped) {
			more = ", ..."
		}
		log(fmt.Sprintf("Skipped %d file(s) outside the folders a backup restores: %s%s", info.SkippedCount, strings.Join(info.Skipped, ", "), more))
	}
	entries, _ := j.ReadDir("")
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), stagingPrefix) {
			_ = j.RemoveAll(e.Name()) // left behind by a crash
		}
	}
	staging := stagingPrefix + randomHex(4)
	defer func() { _ = j.RemoveAll(staging) }()
	wanted := map[string]bool{}
	for _, r := range roots {
		wanted[r] = true
	}
	if _, err := extractZip(path, j, staging+"/new", func(rel string) bool { return !wanted[rootOf(rel)] }, RestoreMaxBytes, RestoreMaxEntries); err != nil {
		return nil, err
	}
	restored, err := swapIn(j, staging, roots, s.SafeIdentity())
	if err != nil {
		return nil, err
	}
	log("Restored: " + strings.Join(restored, ", ") + ".")
	return map[string]any{
		"restored": restored, "files": info.Files, "bytes": info.Bytes, "left_out": leftOut,
		"skipped": info.Skipped, "skipped_count": info.SkippedCount, "map": info.Map,
	}, nil
}

func refuseLinks(j *jail.Jail, rel string) error {
	cur := ""
	for _, part := range strings.Split(rel, "/") {
		cur = strings.Trim(cur+"/"+part, "/")
		if j.IsLink(cur) {
			return fmt.Errorf("%s is a link in the server folder - refused", rel)
		}
	}
	return nil
}

func swapIn(j *jail.Jail, staging string, roots []string, identity string) ([]string, error) {
	type step struct {
		current, old string
		hadOld       bool
	}
	var done []step
	restored := []string{}
	err := func() error {
		for _, root := range roots {
			target := root
			if strings.HasPrefix(root, "server/") {
				target = "server/" + identity
			}
			current, old, fresh := target, staging+"/old/"+target, staging+"/new/"+root
			if err := refuseLinks(j, target); err != nil {
				return err
			}
			_, lerr := j.Lstat(current)
			hadOld := lerr == nil
			if hadOld {
				if _, err := j.MkdirAll(parentOf(old)); err != nil {
					return err
				}
				if j.Rename(current, old) != nil {
					return fmt.Errorf("could not move %s aside (a file in use?)", target)
				}
			}
			done = append(done, step{current, old, hadOld})
			if _, err := j.MkdirAll(parentOf(current)); err != nil {
				return err
			}
			if j.Rename(fresh, current) != nil {
				return fmt.Errorf("could not put the restored %s in place", target)
			}
			restored = append(restored, target)
		}
		return nil
	}()
	if err != nil {
		for i := len(done) - 1; i >= 0; i-- {
			st := done[i]
			if _, e := j.Lstat(st.current); e == nil {
				_ = j.RemoveAll(st.current)
			}
			if st.hadOld {
				_ = j.Rename(st.old, st.current)
			}
		}
		return nil, fmt.Errorf("restore failed, nothing was changed: %v", err)
	}
	return restored, nil
}

/* ---------- uploads (a backup sent here in chunks) ---------- */

// Upload limits: a chunk per request, the largest backup, and parts nobody finished are dropped after a day.
const (
	ChunkBytes  = 32 << 20
	UploadMax   = 50 << 30
	StaleUpload = 24 * time.Hour
)

var uploadID = regexp.MustCompile(`^[a-f0-9]{32}$`)

func (s *Server) partPath(id string) string { return s.BackupDir() + "/.upload-" + id + ".part" }

// The sha256 of what arrived so far is kept next to the part, so finishing never re-reads 50 GB in one request.
func (s *Server) hashPath(id string) string { return s.BackupDir() + "/.upload-" + id + ".sha" }

func loadHash(path string) (hash.Hash, error) {
	h := sha256.New()
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return h, nil
	}
	if err != nil {
		return nil, err
	}
	return h, h.(encoding.BinaryUnmarshaler).UnmarshalBinary(raw)
}

func saveHash(path string, h hash.Hash) error {
	raw, err := h.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		return err
	}
	return config.WriteAtomic(path, raw, 0o600)
}

func (a *Agent) uploadBegin(w http.ResponseWriter, r *http.Request, s *Server) {
	if err := os.MkdirAll(s.BackupDir(), 0o700); err != nil {
		fail(w, 500, "failed", "Could not create the backup folder "+s.BackupDir()+".")
		return
	}
	parts, _ := filepath.Glob(s.BackupDir() + "/.upload-*")
	for _, p := range parts {
		if info, err := os.Lstat(p); err == nil && info.Mode().IsRegular() && time.Since(info.ModTime()) > StaleUpload {
			_ = os.Remove(p)
		}
	}
	id := randomHex(16)
	if err := os.WriteFile(s.partPath(id), nil, 0o600); err != nil {
		fail(w, 500, "failed", "Could not start the upload.")
		return
	}
	writeJSON(w, 201, map[string]any{"id": id, "chunk": ChunkBytes})
}

func (a *Agent) existingPart(w http.ResponseWriter, r *http.Request, s *Server) (string, bool) {
	id := r.PathValue("id")
	if uploadID.MatchString(id) {
		path := s.partPath(id)
		if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() {
			return path, true
		}
	}
	fail(w, 404, "unknown_upload", "No such upload on this machine (finished, cancelled or older than a day).")
	return "", false
}

// uploadChunk: the raw body is one chunk starting at `offset` (must be the size so far; else 409 with the size).
func (a *Agent) uploadChunk(w http.ResponseWriter, r *http.Request, s *Server) {
	path, ok := a.existingPart(w, r, s)
	if !ok {
		return
	}
	var offset int64
	if _, err := fmt.Sscan(r.URL.Query().Get("offset"), &offset); err != nil || offset < 0 {
		invalid(w, "The offset field is required.")
		return
	}
	size := fileSize(path)
	if offset != size {
		writeJSON(w, 409, map[string]any{"error": "offset", "message": fmt.Sprintf("The upload is at byte %d - send the chunk from there.", size), "size": size})
		return
	}
	if free, ok := freeBytes(filepath.Dir(path)); ok && free < ChunkBytes+FreeMargin {
		fail(w, 422, "refused", "Not enough free disk space on this machine for the backup.")
		return
	}
	id := r.PathValue("id")
	h, herr := loadHash(s.hashPath(id))
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil || herr != nil {
		fail(w, 422, "refused", "Could not write the upload.")
		return
	}
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(r.Body, ChunkBytes+1))
	f.Close()
	if err == nil && n <= ChunkBytes && size+n <= UploadMax {
		err = saveHash(s.hashPath(id), h)
	}
	if err != nil || n > ChunkBytes || size+n > UploadMax {
		_ = os.Truncate(path, size)
		msg := "The backup is too large."
		if n > ChunkBytes {
			msg = "Chunk too large."
		} else if err != nil {
			msg = "The chunk did not arrive completely."
		}
		fail(w, 422, "refused", msg)
		return
	}
	writeJSON(w, 200, map[string]any{"size": size + n})
}

func (a *Agent) uploadFinish(w http.ResponseWriter, r *http.Request, s *Server) {
	in, ok := parse(w, r)
	if !ok {
		return
	}
	path, ok := a.existingPart(w, r, s)
	if !ok {
		return
	}
	size, okSize := in.integer("size")
	sum := strings.ToLower(in.str("sha256"))
	if !okSize || size < 1 || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(sum) {
		invalid(w, "size and sha256 are required.")
		return
	}
	id := r.PathValue("id")
	refuse := func(msg string) {
		_ = os.Remove(path)
		_ = os.Remove(s.hashPath(id))
		fail(w, 422, "refused", msg)
	}
	if got := fileSize(path); got != size {
		refuse(fmt.Sprintf("The upload is incomplete (%d of %d bytes).", got, size))
		return
	}
	h, err := loadHash(s.hashPath(id))
	if err != nil {
		refuse("Could not read the upload.")
		return
	}
	if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(h.Sum(nil))), []byte(sum)) != 1 {
		refuse("The upload is damaged (checksum differs).")
		return
	}
	if zr, err := zip.OpenReader(path); err != nil {
		refuse("The upload is not a zip file.")
		return
	} else {
		zr.Close()
	}
	// A normal backup name; os.Link fails when the name exists, so a backup made in the same second is never replaced.
	t := time.Now()
	var name string
	for i := 0; ; i++ {
		name = s.Slug + "-" + t.Format("20060102-150405") + ".zip"
		if err := os.Link(path, s.BackupDir()+"/"+name); err == nil {
			break
		} else if !os.IsExist(err) || i > 120 {
			fail(w, 500, "failed", "Could not store the backup.")
			return
		}
		t = t.Add(time.Second)
	}
	_ = os.Remove(path)
	_ = os.Remove(s.hashPath(id))
	writeJSON(w, 200, map[string]any{"name": name, "size": size})
}

func (a *Agent) uploadCancel(w http.ResponseWriter, r *http.Request, s *Server) {
	if id := r.PathValue("id"); uploadID.MatchString(id) {
		_ = os.Remove(s.partPath(id))
		_ = os.Remove(s.hashPath(id))
	}
	writeJSON(w, 200, map[string]any{"cancelled": true})
}
