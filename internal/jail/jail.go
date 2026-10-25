// Package jail keeps file access inside one server folder.
//
// Every path from the panel is relative ("oxide/plugins/Foo.cs") and is checked segment by segment (the ReRust panel's
// FileManager rules, so both agents accept and refuse the same names). All access then goes through Go's os.Root: the
// folder is opened once and every operation is resolved relative to that handle by the kernel, so a link or a folder
// swapped for a link - also while an operation runs - can never lead outside it. The game server owns the folder's
// contents, so it can try exactly that.
package jail

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

// Error carries an HTTP status for the agent API (422 by default, like the panel's FileManagerException).
type Error struct {
	Status  int
	Message string
}

func (e *Error) Error() string { return e.Message }

func fail(status int, format string, args ...any) error {
	return &Error{Status: status, Message: fmt.Sprintf(format, args...)}
}

// Status of err when it is a jail error (404 for a missing file, 403 for an escape), else 500.
func Status(err error) int {
	var je *Error
	if errors.As(err, &je) {
		return je.Status
	}
	if errors.Is(err, fs.ErrNotExist) {
		return 404
	}
	return 500
}

// Conflict is the status for "already exists" / "changed meanwhile".
const Conflict = 409

var (
	reserved    = regexp.MustCompile(`(?i)^(con|prn|aux|nul|com[0-9¹²³]|lpt[0-9¹²³]|conin\$|conout\$)(\..*)?$`)
	badChars    = regexp.MustCompile(`[\x00-\x1F<>:"/\\|?*]`)
	trailing    = regexp.MustCompile(`[. ]$`)
	absoluteish = regexp.MustCompile(`^/|^[A-Za-z]:`)
)

// Editable extensions open in the panel's editor; anything else is download-only.
var Editable = map[string]bool{}

// Blocked extensions are never accepted as uploads or new file names.
var Blocked = map[string]bool{}

func init() {
	for _, e := range strings.Fields("cs json cfg txt log ini yml yaml xml md csv toml lua js ts py config csproj props targets lang html css sh") {
		Editable[e] = true
	}
	for _, e := range strings.Fields("exe com bat cmd ps1 psm1 vbs vbe wsf wsh msi msp scr lnk reg hta cpl jar url pif") {
		Blocked[e] = true
	}
}

// Jail is one opened server folder. Close it when done.
type Jail struct {
	r   *os.Root
	dir string
}

// Open opens dir as the jail. dir itself must be a real folder, never a link (a game could otherwise replace its
// folder with a link to the agent's own files).
func Open(dir string) (*Jail, error) {
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fail(404, "The server directory does not exist yet. Install the server first.")
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fail(404, "The server directory does not exist yet. Install the server first.")
	}
	return &Jail{r: r, dir: dir}, nil
}

// Close releases the folder handle.
func (j *Jail) Close() error { return j.r.Close() }

// Dir is the folder's path (for messages only - never open by it).
func (j *Jail) Dir() string { return j.dir }

// Root is the os.Root (for callers that need more, e.g. FS() for walking).
func (j *Jail) Root() *os.Root { return j.r }

// Normalise checks a relative path and returns it with forward slashes ("" = the folder itself).
func Normalise(relative string) (string, error) {
	relative = strings.ReplaceAll(relative, `\`, "/")
	if relative == "" || relative == "/" {
		return "", nil
	}
	if absoluteish.MatchString(relative) {
		return "", fail(422, "Absolute paths are not allowed.")
	}
	var parts []string
	for _, part := range strings.Split(strings.Trim(relative, "/"), "/") {
		if err := ValidName(part); err != nil {
			return "", err
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, "/"), nil
}

// ValidName refuses names that are empty, dots, too long, have odd characters or a trailing dot/space.
func ValidName(name string) error {
	if name == "" || name == "." || name == ".." || len(name) > 255 || badChars.MatchString(name) ||
		trailing.MatchString(name) || reserved.MatchString(name) {
		short := name
		if len([]rune(short)) > 60 {
			short = string([]rune(short)[:60])
		}
		return fail(422, "Invalid file or folder name: %s", short)
	}
	return nil
}

// Ext is the lower-case extension without the dot.
func Ext(name string) string {
	return strings.ToLower(strings.TrimPrefix(filepath.Ext(name), "."))
}

// NotBlocked refuses executable-type extensions.
func NotBlocked(name string) error {
	if ext := Ext(name); ext != "" && Blocked[ext] {
		return fail(422, ".%s files are not allowed.", ext)
	}
	return nil
}

// name is what os.Root expects ("." for the folder itself).
func name(rel string) string {
	if rel == "" {
		return "."
	}
	return rel
}

// mapErr turns os.Root errors into API errors: missing = 404, leaving the folder = 403.
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	var je *Error
	if errors.As(err, &je) {
		return err
	}
	if errors.Is(err, fs.ErrNotExist) {
		return fail(404, "File or folder not found.")
	}
	if strings.Contains(err.Error(), "escapes") || errors.Is(err, syscall.ELOOP) || errors.Is(err, fs.ErrPermission) {
		return fail(403, "Path is outside the server directory.")
	}
	return fail(422, "%s", strings.TrimPrefix(err.Error(), "openat "))
}

// Lstat is the item itself (a link is not followed).
func (j *Jail) Lstat(rel string) (fs.FileInfo, error) {
	info, err := j.r.Lstat(name(rel))
	return info, mapErr(err)
}

// Stat follows links - only ones that stay inside the folder.
func (j *Jail) Stat(rel string) (fs.FileInfo, error) {
	info, err := j.r.Stat(name(rel))
	return info, mapErr(err)
}

// Existing checks that rel exists. With follow it must also resolve inside the folder.
func (j *Jail) Existing(rel string, follow bool) (string, fs.FileInfo, error) {
	rel, err := Normalise(rel)
	if err != nil {
		return "", nil, err
	}
	info, err := j.Lstat(rel)
	if err != nil {
		return "", nil, err
	}
	if follow && info.Mode()&os.ModeSymlink != 0 {
		if info, err = j.Stat(rel); err != nil {
			return "", nil, err
		}
	}
	return rel, info, nil
}

// IsLink / IsDir / IsFile inside the folder (missing = false).
func (j *Jail) IsLink(rel string) bool {
	info, err := j.r.Lstat(name(rel))
	return err == nil && info.Mode()&os.ModeSymlink != 0
}

func (j *Jail) IsDir(rel string) bool {
	info, err := j.r.Lstat(name(rel))
	return err == nil && info.IsDir()
}

func (j *Jail) IsFile(rel string) bool {
	info, err := j.r.Lstat(name(rel))
	return err == nil && info.Mode().IsRegular()
}

// NewPath is the relative path for a new item called itemName inside the existing folder directory.
func (j *Jail) NewPath(directory, itemName string) (string, error) {
	if err := ValidName(itemName); err != nil {
		return "", err
	}
	if err := NotBlocked(itemName); err != nil {
		return "", err
	}
	dir, err := Normalise(directory)
	if err != nil {
		return "", err
	}
	if !j.IsDir(dir) {
		if _, err := j.Lstat(dir); err != nil {
			return "", err
		}
		return "", fail(422, "Target is not a folder.")
	}
	rel := strings.Trim(dir+"/"+itemName, "/")
	if _, err := j.r.Lstat(rel); err == nil {
		return "", fail(Conflict, "“%s” already exists.", itemName)
	}
	return rel, nil
}

// MkdirAll creates rel and its parents inside the folder; no part may be a link. Returns rel normalised.
func (j *Jail) MkdirAll(rel string) (string, error) {
	rel, err := Normalise(rel)
	if err != nil {
		return "", err
	}
	cur := ""
	for _, part := range strings.Split(rel, "/") {
		if part == "" {
			continue
		}
		cur = strings.Trim(cur+"/"+part, "/")
		info, err := j.r.Lstat(cur)
		switch {
		case err == nil && info.Mode()&os.ModeSymlink != 0:
			return "", fail(403, "Path is outside the server directory.")
		case err == nil && !info.IsDir():
			return "", fail(422, "Could not create %s.", rel)
		case err != nil:
			if err := j.r.Mkdir(cur, 0o770); err != nil && !j.IsDir(cur) {
				return "", fail(422, "Could not create %s.", rel)
			}
		}
	}
	return rel, nil
}

// OpenRegular opens a regular file for reading - never a FIFO or device (opened non-blocking, then checked on the
// handle itself, so a swap after the check can't change what is read). maxBytes < 0 = no limit.
func (j *Jail) OpenRegular(rel string, maxBytes int64) (*os.File, fs.FileInfo, error) {
	rel, err := Normalise(rel)
	if err != nil {
		return nil, nil, err
	}
	f, err := j.r.OpenFile(name(rel), os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, mapErr(err)
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil, nil, fail(422, "Not a file.")
	}
	if maxBytes >= 0 && info.Size() > maxBytes {
		f.Close()
		return nil, nil, fail(413, "The file is too large to read this way.")
	}
	return f, info, nil
}

// ReadRegular reads a whole regular file of at most maxBytes (also when it grows while being read).
func (j *Jail) ReadRegular(rel string, maxBytes int64) ([]byte, fs.FileInfo, error) {
	f, info, err := j.OpenRegular(rel, maxBytes)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, nil, fail(422, "Could not read the file.")
	}
	if int64(len(data)) > maxBytes {
		return nil, nil, fail(413, "The file is too large to read this way.")
	}
	return data, info, nil
}

// WriteAtomic writes rel through a new temporary file (O_EXCL) and a rename - a link at rel is replaced, never
// written through. Missing folders are made. The mode of an existing file is kept.
func (j *Jail) WriteAtomic(rel string, data []byte, mode fs.FileMode) error {
	return j.WriteAtomicFrom(rel, bytes.NewReader(data), int64(len(data)), mode)
}

// WriteAtomicFrom is WriteAtomic from a reader (at most maxBytes; more = refused).
func (j *Jail) WriteAtomicFrom(rel string, src io.Reader, maxBytes int64, mode fs.FileMode) error {
	rel, err := Normalise(rel)
	if err != nil {
		return err
	}
	if rel == "" {
		return fail(422, "A file name is required.")
	}
	dir := path.Dir(rel)
	if dir == "." {
		dir = ""
	}
	if _, err := j.MkdirAll(dir); err != nil {
		return err
	}
	if info, err := j.r.Lstat(rel); err == nil {
		if info.IsDir() {
			return fail(403, "Cannot write there.")
		}
		if info.Mode().IsRegular() {
			mode = info.Mode().Perm()
		}
	}
	tmp := strings.TrimPrefix(dir+"/.rerust-"+randomName()+".tmp", "/")
	f, err := j.r.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return fail(422, "Could not save the file.")
	}
	n, werr := io.Copy(f, io.LimitReader(src, maxBytes+1))
	if werr == nil && n > maxBytes {
		werr = fail(413, "The file is too large.")
	}
	if werr == nil {
		werr = f.Chmod(mode) // on the handle: never through a swapped link
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = j.r.Rename(tmp, rel)
	}
	if werr != nil {
		_ = j.r.Remove(tmp)
		return fail(422, "Could not save the file. It may be locked by the server.")
	}
	return nil
}

// Create makes a new empty file (fails when anything exists there).
func (j *Jail) Create(rel string, mode fs.FileMode) (*os.File, error) {
	f, err := j.r.OpenFile(name(rel), os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	return f, mapErr(err)
}

// Mkdir makes one folder.
func (j *Jail) Mkdir(rel string) error { return mapErr(j.r.Mkdir(name(rel), 0o770)) }

// Rename inside the folder.
func (j *Jail) Rename(from, to string) error { return mapErr(j.r.Rename(name(from), name(to))) }

// Remove one file, empty folder or link (a link itself, never its target).
func (j *Jail) Remove(rel string) error { return mapErr(j.r.Remove(name(rel))) }

// RemoveAll deletes rel recursively, never following links (os.Root resolves every step relative to the handle).
func (j *Jail) RemoveAll(rel string) error {
	if rel == "" {
		return fail(422, "The server folder itself cannot be deleted.")
	}
	return mapErr(j.r.RemoveAll(rel))
}

// ReadDir lists a folder.
func (j *Jail) ReadDir(rel string) ([]fs.DirEntry, error) {
	f, err := j.r.Open(name(rel))
	if err != nil {
		return nil, mapErr(err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.IsDir() {
		return nil, fail(422, "Not a folder.")
	}
	entries, err := f.ReadDir(-1)
	return entries, mapErr(err)
}

// FS is the folder as an fs.FS (for walking it).
func (j *Jail) FS() fs.FS { return j.r.FS() }

/* ---------- helpers for paths the game can't reach (agent state, backups) ---------- */

// IsLink reports a symlink (never followed).
func IsLink(p string) bool {
	info, err := os.Lstat(p)
	return err == nil && info.Mode()&os.ModeSymlink != 0
}

// IsDir reports a real folder (a link to one is not).
func IsDir(p string) bool {
	info, err := os.Lstat(p)
	return err == nil && info.IsDir()
}

// IsFile reports a real regular file (a link to one is not).
func IsFile(p string) bool {
	info, err := os.Lstat(p)
	return err == nil && info.Mode().IsRegular()
}

// DeleteTree deletes dir (a real folder) recursively through os.Root - links are removed, never followed.
func DeleteTree(dir string) bool {
	info, err := os.Lstat(dir)
	if err != nil {
		return os.IsNotExist(err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return os.Remove(dir) == nil
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		return false
	}
	entries, _ := r.FS().(fs.ReadDirFS).ReadDir(".")
	ok := true
	for _, e := range entries {
		if r.RemoveAll(e.Name()) != nil {
			ok = false
		}
	}
	r.Close()
	return os.Remove(dir) == nil && ok
}

func randomName() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
