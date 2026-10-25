package agent

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/Zand3rsCode/rerust-agent/internal/jail"
)

// MaxRead is the largest file read through /files/read (and hashed by /files/stat); MaxEdit the File Manager's
// editor limit; MaxList entries listed per folder.
const (
	MaxRead    = 8 << 20
	MaxEdit    = 2 << 20
	MaxList    = 5000
	PluginHead = 65536
	MaxUpload  = 512 << 20
)

var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

func jailFail(w http.ResponseWriter, err error, code string) {
	status := jail.Status(err)
	if code == "" {
		code = "file_error"
		if status == 404 {
			code = "not_found"
		}
	}
	fail(w, status, code, err.Error())
}

func sha1Hex(b []byte) string { s := sha1.Sum(b); return hex.EncodeToString(s[:]) }

// atomicWrite writes through a temporary file + rename; falls back to writing in place when the target can't be
// replaced but is still writable.
func atomicWrite(path string, content []byte) error {
	dir := filepath.Dir(path)
	tmp := dir + "/.rerust-" + randomHex(6) + ".tmp"
	mode := os.FileMode(0o644)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	if err := os.WriteFile(tmp, content, mode); err == nil {
		if os.Rename(tmp, path) == nil {
			return nil
		}
	}
	_ = os.Remove(tmp)
	if err := os.WriteFile(path, content, mode); err != nil {
		return &jail.Error{Status: 422, Message: "Could not save the file. It may be locked by the server."}
	}
	return nil
}

/* ---------- /files: the panel's own files (server.cfg, plugin data) ---------- */

func (a *Agent) fileWrite(w http.ResponseWriter, r *http.Request, s *Server) {
	in, ok := parse(w, r)
	if !ok {
		return
	}
	path := in.str("path")
	if path == "" || len(path) > 1024 || !in.has("content") {
		invalid(w, "path and content are required.")
		return
	}
	content, err := base64.StdEncoding.DecodeString(in.str("content"))
	if err != nil {
		fail(w, 422, "bad_content", "The content must be base64.")
		return
	}
	// Writing creates the server's own folder when missing (never through a link).
	if !jail.IsDir(s.Dir()) && !jail.IsLink(s.Dir()) {
		_ = os.MkdirAll(s.Dir(), 0o755)
	}
	j, err := jail.New(s.Dir())
	if err != nil {
		jailFail(w, err, "")
		return
	}
	rel, err := j.Normalise(path)
	if err == nil && rel == "" {
		err = &jail.Error{Status: 422, Message: "A file name is required."}
	}
	if err != nil {
		jailFail(w, err, "")
		return
	}
	parent := ""
	if i := strings.LastIndex(rel, "/"); i >= 0 {
		parent = rel[:i]
	}
	if _, err := j.MkdirAll(parent); err != nil {
		jailFail(w, err, "")
		return
	}
	full := j.Root() + "/" + rel
	if jail.IsLink(full) || jail.IsDir(full) {
		fail(w, 403, "file_error", "Cannot write there.")
		return
	}
	if in.truthy("if_changed") {
		if old, err := os.ReadFile(full); err == nil && bytes.Equal(old, content) {
			writeJSON(w, 200, map[string]any{"written": false, "size": len(content)})
			return
		}
	}
	if err := atomicWrite(full, content); err != nil {
		jailFail(w, err, "")
		return
	}
	writeJSON(w, 200, map[string]any{"written": true, "size": len(content)})
}

func (a *Agent) fileRead(w http.ResponseWriter, r *http.Request, s *Server) {
	in, _ := readInput(r)
	path := in.str("path")
	if path == "" || len(path) > 1024 {
		invalid(w, "The path field is required.")
		return
	}
	j, err := jail.New(s.Dir())
	if err != nil {
		jailFail(w, err, "")
		return
	}
	full, err := j.Existing(path, true)
	if err != nil {
		jailFail(w, err, "")
		return
	}
	info, err := os.Stat(full)
	if err != nil || !info.Mode().IsRegular() {
		fail(w, 422, "file_error", "Not a file.")
		return
	}
	if info.Size() > MaxRead {
		fail(w, 413, "file_error", "The file is too large to read this way.")
		return
	}
	content, err := os.ReadFile(full)
	if err != nil {
		fail(w, 422, "file_error", "Could not read the file.")
		return
	}
	writeJSON(w, 200, map[string]any{"content": base64.StdEncoding.EncodeToString(content), "size": info.Size()})
}

func (a *Agent) fileStat(w http.ResponseWriter, r *http.Request, s *Server) {
	in, _ := readInput(r)
	missing := map[string]any{"exists": false, "dir": false, "size": 0, "mtime": 0, "sha1": nil}
	j, err := jail.New(s.Dir())
	if err != nil {
		writeJSON(w, 200, missing)
		return
	}
	full, err := j.Existing(in.str("path"), true)
	if err != nil {
		if jail.Status(err) == 404 {
			writeJSON(w, 200, missing)
			return
		}
		jailFail(w, err, "")
		return
	}
	info, _ := os.Stat(full)
	reply := map[string]any{"exists": true, "dir": info.IsDir(), "size": 0, "mtime": info.ModTime().Unix(), "sha1": nil}
	if info.Mode().IsRegular() {
		reply["size"] = info.Size()
		if info.Size() <= MaxRead {
			if raw, err := os.ReadFile(full); err == nil {
				reply["sha1"] = sha1Hex(raw)
			}
		}
	}
	writeJSON(w, 200, reply)
}

func (a *Agent) fileDelete(w http.ResponseWriter, r *http.Request, s *Server) {
	in, _ := readInput(r)
	path := in.str("path")
	if path == "" {
		invalid(w, "The path field is required.")
		return
	}
	j, err := jail.New(s.Dir())
	if err != nil {
		writeJSON(w, 200, map[string]any{"deleted": false})
		return
	}
	full, err := j.Existing(path, false)
	if err != nil {
		if jail.Status(err) == 404 {
			writeJSON(w, 200, map[string]any{"deleted": false})
			return
		}
		jailFail(w, err, "")
		return
	}
	if jail.IsLink(full) || !jail.IsFile(full) {
		fail(w, 403, "file_error", "Only files can be deleted this way.")
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": os.Remove(full) == nil})
}

/* ---------- /fm: File Manager + Plugins page ---------- */

func language(rel string) string {
	switch jail.Ext(rel) {
	case "cs":
		return "csharp"
	case "json", "lang":
		return "json"
	case "yml", "yaml":
		return "yaml"
	case "xml", "config", "csproj", "props", "targets", "html":
		return "xml"
	case "lua":
		return "lua"
	case "js", "ts":
		return "javascript"
	case "cfg", "ini", "toml":
		return "properties"
	case "sh":
		return "shell"
	case "py":
		return "python"
	case "css":
		return "css"
	}
	return "text"
}

// naturalLess is a case-insensitive natural order (file2 before file10), like PHP's strnatcasecmp.
func naturalLess(a, b string) bool {
	a, b = strings.ToLower(a), strings.ToLower(b)
	for a != "" && b != "" {
		if isDigit(a[0]) && isDigit(b[0]) {
			na, ra := splitDigits(a)
			nb, rb := splitDigits(b)
			ta, tb := strings.TrimLeft(na, "0"), strings.TrimLeft(nb, "0")
			if len(ta) != len(tb) {
				return len(ta) < len(tb)
			}
			if ta != tb {
				return ta < tb
			}
			a, b = ra, rb
			continue
		}
		if a[0] != b[0] {
			return a[0] < b[0]
		}
		a, b = a[1:], b[1:]
	}
	return len(a) < len(b)
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func splitDigits(s string) (string, string) {
	i := 0
	for i < len(s) && isDigit(s[i]) {
		i++
	}
	return s[:i], s[i:]
}

var (
	infoPattern = regexp.MustCompile(`\[\s*Info\s*\(\s*"((?:[^"\\]|\\.)*)"\s*,\s*"((?:[^"\\]|\\.)*)"\s*,\s*(?:"((?:[^"\\]|\\.)*)"|([\d.]+))`)
	descPattern = regexp.MustCompile(`\[\s*Description\s*\(\s*"((?:[^"\\]|\\.)*)"`)
)

// infoHead is only the [Info(...)] and [Description(...)] parts of a plugin's source (the panel parses them).
func infoHead(src string) string {
	var parts []string
	for _, p := range []*regexp.Regexp{infoPattern, descPattern} {
		if m := p.FindString(src); m != "" {
			parts = append(parts, m)
		}
	}
	return strings.Join(parts, "\n")
}

func (a *Agent) fmOp(w http.ResponseWriter, r *http.Request, s *Server) {
	in, ok := parse(w, r)
	if !ok {
		return
	}
	j, err := jail.New(s.Dir())
	if err != nil {
		jailFail(w, err, "file_error")
		return
	}
	reply, err := fmDo(j, in)
	if err != nil {
		jailFail(w, err, "file_error")
		return
	}
	writeJSON(w, 200, reply)
}

func bad(msg string) error { return &jail.Error{Status: 422, Message: msg} }

func fmDo(j *jail.Jail, in input) (any, error) {
	path := in.str("path")
	if len(path) > 1024 {
		return nil, bad("The path is too long.")
	}
	name := in.str("name")
	needName := func() error {
		if name == "" || len(name) > 255 {
			return bad("The name field is required.")
		}
		return nil
	}
	switch in.str("op") {
	case "list":
		return fmList(j, path)
	case "read":
		return fmRead(j, path)
	case "write":
		if path == "" || !in.has("content") {
			return nil, bad("path and content are required.")
		}
		var hash *string
		if h := in.str("hash"); h != "" {
			if len(h) != 40 {
				return nil, bad("The hash must be 40 characters.")
			}
			hash = &h
		}
		h, err := fmWrite(j, path, in.str("content"), hash)
		return map[string]any{"hash": h}, err
	case "create_file":
		if err := needName(); err != nil {
			return nil, err
		}
		abs, rel, err := j.NewPath(path, name)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(abs, nil, 0o644); err != nil {
			return nil, bad("Could not create the file.")
		}
		return map[string]any{"path": rel}, nil
	case "create_folder":
		if err := needName(); err != nil {
			return nil, err
		}
		abs, rel, err := j.NewPath(path, name)
		if err != nil {
			return nil, err
		}
		if err := os.Mkdir(abs, 0o755); err != nil {
			return nil, bad("Could not create the folder.")
		}
		return map[string]any{"path": rel}, nil
	case "rename":
		if path == "" {
			return nil, bad("The path field is required.")
		}
		if err := needName(); err != nil {
			return nil, err
		}
		rel, err := fmRename(j, path, name)
		return map[string]any{"path": rel}, err
	case "delete":
		if path == "" {
			return nil, bad("The path field is required.")
		}
		return map[string]any{"ok": true}, fmDelete(j, path)
	case "is_file":
		return map[string]any{"file": isFileIn(j, path)}, nil
	case "is_dir":
		return map[string]any{"dir": isDirIn(j, path)}, nil
	case "mkdir":
		rel, err := j.MkdirAll(path)
		return map[string]any{"path": rel}, err
	case "dirs":
		paths, ok := in.strings("paths")
		if !ok || len(paths) == 0 || len(paths) > 50 {
			return nil, bad("paths (1 - 50) are required.")
		}
		dirs := []string{}
		for _, p := range paths {
			if isDirIn(j, p) {
				dirs = append(dirs, p)
			}
		}
		return map[string]any{"dirs": dirs}, nil
	case "move":
		from, to := in.str("from"), in.str("to_dir")
		if from == "" || to == "" {
			return nil, bad("from and to_dir are required.")
		}
		rel, err := fmMove(j, from, to)
		return map[string]any{"path": rel}, err
	case "plugins":
		fw, cfgDir, disabled := in.str("framework"), in.str("config_dir"), in.str("disabled_dir")
		if (fw != "oxide" && fw != "carbon") || (cfgDir != "config" && cfgDir != "configs") || !regexp.MustCompile(`^[a-z-]{1,32}$`).MatchString(disabled) {
			return nil, bad("framework, config_dir and disabled_dir are required.")
		}
		return map[string]any{"plugins": fmPlugins(j, fw, cfgDir, disabled)}, nil
	}
	return nil, &jail.Error{Status: 400, Message: "Unknown file operation."}
}

func fmList(j *jail.Jail, path string) (any, error) {
	rel, err := j.Normalise(path)
	if err != nil {
		return nil, err
	}
	dir, err := j.Existing(rel, true)
	if err != nil {
		return nil, err
	}
	if !jail.IsDir(dir) {
		return nil, bad("Not a folder.")
	}
	items, _ := os.ReadDir(dir)
	entries := []map[string]any{}
	truncated := false
	for _, item := range items {
		if len(entries) >= MaxList {
			truncated = true
			break
		}
		name := item.Name()
		full := dir + "/" + name
		info, _ := os.Lstat(full)
		isLink := info != nil && info.Mode()&os.ModeSymlink != 0
		isDir := !isLink && item.IsDir()
		kind := "file"
		if isLink {
			kind = "link"
		} else if isDir {
			kind = "dir"
		}
		var size, modified any
		if !isDir && !isLink && info != nil {
			size = info.Size()
		}
		if info != nil {
			modified = info.ModTime().Unix()
		}
		ext := jail.Ext(name)
		entries = append(entries, map[string]any{
			"name":     name,
			"path":     strings.Trim(rel+"/"+name, "/"),
			"type":     kind,
			"size":     size,
			"modified": modified,
			"editable": !isDir && !isLink && jail.Editable[ext],
			"ext":      ext,
		})
	}
	sort.SliceStable(entries, func(x, y int) bool {
		dx, dy := entries[x]["type"] == "dir", entries[y]["type"] == "dir"
		if dx != dy {
			return dx
		}
		return naturalLess(entries[x]["name"].(string), entries[y]["name"].(string))
	})
	return map[string]any{"path": rel, "entries": entries, "truncated": truncated}, nil
}

func fmRead(j *jail.Jail, path string) (any, error) {
	rel, err := j.Normalise(path)
	if err != nil {
		return nil, err
	}
	full, err := j.Existing(rel, true)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(full)
	if err != nil || !info.Mode().IsRegular() || jail.IsLink(full) {
		return nil, bad("Not a file.")
	}
	if info.Size() > MaxEdit {
		return nil, bad("File is too large to edit in the browser. Download it instead.")
	}
	raw, err := os.ReadFile(full)
	if err != nil {
		return nil, bad("Could not read the file.")
	}
	content := bytes.TrimPrefix(raw, utf8BOM)
	if bytes.IndexByte(content, 0) >= 0 || !utf8.Valid(content) {
		return nil, bad("This looks like a binary file and cannot be edited. Download it instead.")
	}
	return map[string]any{
		"path":     rel,
		"content":  strings.ReplaceAll(string(content), "\r\n", "\n"),
		"hash":     sha1Hex(raw),
		"size":     info.Size(),
		"modified": info.ModTime().Unix(),
		"language": language(rel),
	}, nil
}

func fmWrite(j *jail.Jail, path, content string, expected *string) (string, error) {
	rel, err := j.Normalise(path)
	if err != nil {
		return "", err
	}
	full, err := j.Existing(rel, true)
	if err != nil {
		return "", err
	}
	if !jail.IsFile(full) || jail.IsLink(full) {
		return "", bad("Not a file.")
	}
	if !jail.Editable[jail.Ext(full)] {
		return "", bad("This file type cannot be edited.")
	}
	if len(content) > MaxEdit {
		return "", bad("Content is too large.")
	}
	if !utf8.ValidString(content) || strings.IndexByte(content, 0) >= 0 {
		return "", bad("Content must be UTF-8 text.")
	}
	original, _ := os.ReadFile(full)
	if expected != nil && sha1Hex(original) != strings.ToLower(*expected) {
		return "", &jail.Error{Status: jail.Conflict, Message: "The file was changed on disk after you opened it."}
	}
	// Keep the original BOM and line endings.
	content = strings.ReplaceAll(content, "\r\n", "\n")
	if bytes.Contains(original, []byte("\r\n")) {
		content = strings.ReplaceAll(content, "\n", "\r\n")
	}
	out := []byte(content)
	if bytes.HasPrefix(original, utf8BOM) {
		out = append(append([]byte{}, utf8BOM...), out...)
	}
	if err := atomicWrite(full, out); err != nil {
		return "", err
	}
	return sha1Hex(out), nil
}

func fmRename(j *jail.Jail, path, name string) (string, error) {
	rel, err := j.Normalise(path)
	if err != nil {
		return "", err
	}
	if rel == "" {
		return "", bad("The server folder itself cannot be renamed.")
	}
	from, err := j.Existing(rel, false)
	if err != nil {
		return "", err
	}
	parent := ""
	if i := strings.LastIndex(rel, "/"); i >= 0 {
		parent = rel[:i]
	}
	to, newRel, err := j.NewPath(parent, name)
	if err != nil {
		return "", err
	}
	if err := os.Rename(from, to); err != nil {
		return "", bad("Rename failed. The file may be in use by the server.")
	}
	return newRel, nil
}

func fmDelete(j *jail.Jail, path string) error {
	rel, err := j.Normalise(path)
	if err != nil {
		return err
	}
	if rel == "" {
		return bad("The server folder itself cannot be deleted.")
	}
	full, err := j.Existing(rel, false)
	if err != nil {
		return err
	}
	if !jail.DeleteTree(full) {
		return bad("Some items could not be deleted. They may be in use by the server.")
	}
	return nil
}

func isFileIn(j *jail.Jail, path string) bool {
	p, err := j.Existing(path, false)
	return err == nil && jail.IsFile(p) && !jail.IsLink(p)
}

func isDirIn(j *jail.Jail, path string) bool {
	p, err := j.Existing(path, false)
	return err == nil && jail.IsDir(p) && !jail.IsLink(p)
}

func fmMove(j *jail.Jail, from, toDir string) (string, error) {
	source, err := j.Existing(from, false)
	if err != nil {
		return "", err
	}
	if !jail.IsFile(source) || jail.IsLink(source) {
		return "", bad("Not a file.")
	}
	if _, err := j.MkdirAll(toDir); err != nil {
		return "", err
	}
	target, rel, err := j.NewPath(toDir, filepath.Base(source))
	if err != nil {
		return "", err
	}
	if err := os.Rename(source, target); err != nil {
		return "", bad("Could not move the file. It may be in use - try again.")
	}
	return rel, nil
}

func fmPlugins(j *jail.Jail, framework, configDir, disabledDir string) []map[string]any {
	root := j.Root()
	out := []map[string]any{}
	for _, folder := range []struct {
		name     string
		disabled bool
	}{{"plugins", false}, {disabledDir, true}} {
		dir := root + "/" + framework + "/" + folder.name
		if !jail.IsDir(dir) || jail.IsLink(dir) || jail.IsLink(root+"/"+framework) {
			continue
		}
		items, _ := os.ReadDir(dir)
		for _, item := range items {
			full := dir + "/" + item.Name()
			info, err := os.Lstat(full)
			if err != nil || !info.Mode().IsRegular() || filepath.Ext(item.Name()) != ".cs" {
				continue
			}
			name := strings.TrimSuffix(item.Name(), ".cs")
			head := make([]byte, PluginHead)
			n := 0
			if f, err := os.Open(full); err == nil {
				n, _ = io.ReadFull(f, head)
				f.Close()
			}
			cfg := root + "/" + framework + "/" + configDir + "/" + name + ".json"
			out = append(out, map[string]any{
				"name":       name,
				"disabled":   folder.disabled,
				"head":       base64.StdEncoding.EncodeToString([]byte(infoHead(string(head[:n])))),
				"size":       info.Size(),
				"modified":   info.ModTime().Unix(),
				"has_config": jail.IsFile(cfg) && !jail.IsLink(cfg),
			})
		}
	}
	return out
}

/* ---------- upload / download ---------- */

func (a *Agent) fmUpload(w http.ResponseWriter, r *http.Request, s *Server) {
	r.Body = http.MaxBytesReader(w, r.Body, MaxUpload)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		fail(w, 413, "file_error", "The upload is too large or not a form.")
		return
	}
	defer r.MultipartForm.RemoveAll()
	files := r.MultipartForm.File["files[]"]
	if len(files) == 0 {
		files = r.MultipartForm.File["files"]
	}
	if len(files) == 0 || len(files) > 20 {
		invalid(w, "1 - 20 files are required.")
		return
	}
	j, err := jail.New(s.Dir())
	if err != nil {
		jailFail(w, err, "file_error")
		return
	}
	truthy := func(k string) bool { v := r.FormValue(k); return v == "1" || v == "true" }
	path := r.FormValue("path")
	if truthy("create") {
		if _, err := j.MkdirAll(path); err != nil {
			jailFail(w, err, "file_error")
			return
		}
	}
	rel, err := j.Normalise(path)
	if err != nil {
		jailFail(w, err, "file_error")
		return
	}
	dir, err := j.Existing(rel, true)
	if err != nil {
		jailFail(w, err, "file_error")
		return
	}
	if !jail.IsDir(dir) || jail.IsLink(dir) {
		fail(w, 422, "file_error", "Target is not a folder.")
		return
	}
	// Validate all files before storing any.
	overwrite := truthy("overwrite")
	type planned struct {
		index int
		name  string
	}
	var plan []planned
	for i, fh := range files {
		name := filepath.Base(strings.ReplaceAll(fh.Filename, `\`, "/"))
		if err := jail.ValidName(name); err != nil {
			jailFail(w, err, "file_error")
			return
		}
		if err := jail.NotBlocked(name); err != nil {
			jailFail(w, err, "file_error")
			return
		}
		target := dir + "/" + name
		if jail.IsLink(target) || jail.IsDir(target) {
			fail(w, 422, "file_error", "“"+name+"” is a folder or link and cannot be replaced.")
			return
		}
		if fileExists(target) && !overwrite {
			fail(w, 409, "file_error", "“"+name+"” already exists.")
			return
		}
		plan = append(plan, planned{i, name})
	}
	stored := []string{}
	for _, p := range plan {
		src, err := files[p.index].Open()
		if err != nil {
			fail(w, 422, "file_error", "Could not read "+p.name+".")
			return
		}
		tmp := dir + "/.rerust-" + randomHex(6) + ".tmp"
		out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o644)
		if err == nil {
			_, err = io.Copy(out, src)
			out.Close()
		}
		src.Close()
		if err == nil {
			err = os.Rename(tmp, dir+"/"+p.name)
		}
		if err != nil {
			_ = os.Remove(tmp)
			fail(w, 422, "file_error", "Could not store "+p.name+".")
			return
		}
		stored = append(stored, strings.Trim(rel+"/"+p.name, "/"))
	}
	writeJSON(w, 200, map[string]any{"paths": stored})
}

func (a *Agent) fmDownload(w http.ResponseWriter, r *http.Request, s *Server) {
	j, err := jail.New(s.Dir())
	if err != nil {
		jailFail(w, err, "file_error")
		return
	}
	full, err := j.Existing(r.URL.Query().Get("path"), true)
	if err == nil && !jail.IsFile(full) {
		err = bad("Only files can be downloaded.")
	}
	if err != nil {
		jailFail(w, err, "file_error")
		return
	}
	serveFile(w, full, filepath.Base(full), "application/octet-stream")
}

func serveFile(w http.ResponseWriter, path, name, contentType string) {
	f, err := os.Open(path)
	if err != nil {
		fail(w, 404, "not_found", "The file is missing.")
		return
	}
	defer f.Close()
	if info, err := f.Stat(); err == nil {
		w.Header().Set("Content-Length", itoa(info.Size()))
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
	_, _ = io.Copy(w, f)
}

/* ---------- maps ---------- */

var mapName = regexp.MustCompile(`^map_(\d{3,5})_(\d{1,10})\.png$`)

func (a *Agent) maps(w http.ResponseWriter, r *http.Request, s *Server) {
	out := []map[string]any{}
	items, _ := os.ReadDir(s.Dir())
	for _, item := range items {
		info, err := os.Lstat(s.Dir() + "/" + item.Name())
		if err != nil || !info.Mode().IsRegular() || !mapName.MatchString(item.Name()) {
			continue
		}
		out = append(out, map[string]any{"name": item.Name(), "size": info.Size(), "mtime": info.ModTime().Unix()})
	}
	writeJSON(w, 200, map[string]any{"maps": out})
}
