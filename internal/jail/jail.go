// Package jail keeps file access inside one server folder.
//
// Every path from the panel is relative ("oxide/plugins/Foo.cs"). It is checked segment by segment, then resolved
// with the links followed, and the result must still be inside the root - a link can never lead out of it.
// The rules are the ReRust panel's FileManager rules, so both agents accept and refuse the same names.
package jail

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
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

// Status of err when it is a jail error, else 500.
func Status(err error) int {
	var je *Error
	if errors.As(err, &je) {
		return je.Status
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

// Jail is one server folder.
type Jail struct {
	root string // real path, no trailing slash
}

// New opens the jail for an existing folder (404 when it doesn't exist yet).
func New(dir string) (*Jail, error) {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return nil, fail(404, "The server directory does not exist yet. Install the server first.")
	}
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, fail(404, "The server directory does not exist yet. Install the server first.")
	}
	return &Jail{root: strings.TrimRight(real, "/")}, nil
}

// Root is the folder's real path.
func (j *Jail) Root() string { return j.root }

// Normalise checks a relative path and returns it with forward slashes ("" = the root).
func (j *Jail) Normalise(relative string) (string, error) {
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

func (j *Jail) abs(relative string) string {
	if relative == "" {
		return j.root
	}
	return j.root + "/" + relative
}

func (j *Jail) inside(real string, allowRoot bool) bool {
	real = strings.TrimRight(real, "/")
	if real == j.root {
		return allowRoot
	}
	return strings.HasPrefix(real, j.root+"/")
}

// Existing returns the absolute path of an existing item inside the root. With follow false a link is returned as
// it is (to rename or delete the link itself); otherwise its target must be inside the root too.
func (j *Jail) Existing(relative string, follow bool) (string, error) {
	relative, err := j.Normalise(relative)
	if err != nil {
		return "", err
	}
	absolute := j.abs(relative)
	if _, err := os.Lstat(absolute); err != nil {
		return "", fail(404, "File or folder not found.")
	}
	parent := j.root
	if relative != "" {
		parent, err = filepath.EvalSymlinks(filepath.Dir(absolute))
		if err != nil || !j.inside(parent, true) {
			return "", fail(403, "Path is outside the server directory.")
		}
	}
	if IsLink(absolute) && !follow {
		return absolute, nil
	}
	real, err := filepath.EvalSymlinks(absolute)
	if err != nil || !j.inside(real, true) {
		return "", fail(403, "Path is outside the server directory.")
	}
	return absolute, nil
}

// NewPath is the absolute + relative path for a new item called name inside the existing folder directory.
func (j *Jail) NewPath(directory, name string) (string, string, error) {
	if err := ValidName(name); err != nil {
		return "", "", err
	}
	if err := NotBlocked(name); err != nil {
		return "", "", err
	}
	dir, err := j.Existing(directory, true)
	if err != nil {
		return "", "", err
	}
	if !IsDir(dir) || IsLink(dir) {
		return "", "", fail(422, "Target is not a folder.")
	}
	absolute := dir + "/" + name
	if _, err := os.Lstat(absolute); err == nil {
		return "", "", fail(Conflict, "“%s” already exists.", name)
	}
	norm, _ := j.Normalise(directory)
	return absolute, strings.Trim(norm+"/"+name, "/"), nil
}

// NotBlocked refuses executable-type extensions.
func NotBlocked(name string) error {
	if ext := Ext(name); ext != "" && Blocked[ext] {
		return fail(422, ".%s files are not allowed.", ext)
	}
	return nil
}

// MkdirAll creates relative (and its parents) inside the root, never through a link. Returns it normalised.
func (j *Jail) MkdirAll(relative string) (string, error) {
	relative, err := j.Normalise(relative)
	if err != nil {
		return "", err
	}
	dir := j.root
	if relative != "" {
		for _, part := range strings.Split(relative, "/") {
			dir += "/" + part
			if IsLink(dir) {
				return "", fail(403, "Path is outside the server directory.")
			}
			if !IsDir(dir) {
				if _, err := os.Lstat(dir); err == nil {
					return "", fail(422, "Could not create %s.", relative)
				}
				if err := os.Mkdir(dir, 0o755); err != nil && !IsDir(dir) {
					return "", fail(422, "Could not create %s.", relative)
				}
			}
		}
	}
	if _, err := j.Existing(relative, true); err != nil {
		return "", err
	}
	return relative, nil
}

// IsLink reports a symlink (never followed).
func IsLink(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode()&os.ModeSymlink != 0
}

// IsDir reports a folder (following links).
func IsDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// IsFile reports a regular file (following links).
func IsFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// DeleteTree deletes a file or folder recursively without ever following links (a link is removed, its target is
// untouched). True when everything is gone.
func DeleteTree(path string) bool {
	info, err := os.Lstat(path)
	if err != nil {
		return os.IsNotExist(err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return os.Remove(path) == nil
	}
	entries, _ := os.ReadDir(path)
	ok := true
	for _, e := range entries {
		ok = DeleteTree(path+"/"+e.Name()) && ok
	}
	return os.Remove(path) == nil && ok
}
