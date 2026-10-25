package agent

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"io"
	"mime"
	"net/http"
	"path"
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

func bad(msg string) error { return &jail.Error{Status: 422, Message: msg} }

// openJail opens the server folder or answers the error.
func openJail(w http.ResponseWriter, s *Server, code string) (*jail.Jail, bool) {
	j, err := jail.Open(s.Dir())
	if err != nil {
		jailFail(w, err, code)
		return nil, false
	}
	return j, true
}

/* ---------- /files: the panel's own files (server.cfg, plugin data) ---------- */

func (a *Agent) fileWrite(w http.ResponseWriter, r *http.Request, s *Server) {
	in, ok := parse(w, r)
	if !ok {
		return
	}
	p := in.str("path")
	if p == "" || len(p) > 1024 || !in.has("content") {
		invalid(w, "path and content are required.")
		return
	}
	content, err := base64.StdEncoding.DecodeString(in.str("content"))
	if err != nil {
		fail(w, 422, "bad_content", "The content must be base64.")
		return
	}
	// Writing creates the server's own folder when missing (never through a link).
	if err := s.ensureDir(); err != nil {
		fail(w, 422, "file_error", err.Error())
		return
	}
	j, ok := openJail(w, s, "")
	if !ok {
		return
	}
	defer j.Close()
	rel, err := jail.Normalise(p)
	if err == nil && rel == "" {
		err = bad("A file name is required.")
	}
	if err != nil {
		jailFail(w, err, "")
		return
	}
	if in.truthy("if_changed") {
		if old, _, err := j.ReadRegular(rel, int64(len(content))); err == nil && bytes.Equal(old, content) {
			writeJSON(w, 200, map[string]any{"written": false, "size": len(content)})
			return
		}
	}
	if err := j.WriteAtomic(rel, content, 0o660); err != nil {
		jailFail(w, err, "")
		return
	}
	writeJSON(w, 200, map[string]any{"written": true, "size": len(content)})
}

func (a *Agent) fileRead(w http.ResponseWriter, r *http.Request, s *Server) {
	in, _ := readInput(r)
	p := in.str("path")
	if p == "" || len(p) > 1024 {
		invalid(w, "The path field is required.")
		return
	}
	j, ok := openJail(w, s, "")
	if !ok {
		return
	}
	defer j.Close()
	content, info, err := j.ReadRegular(p, MaxRead)
	if err != nil {
		jailFail(w, err, "")
		return
	}
	writeJSON(w, 200, map[string]any{"content": base64.StdEncoding.EncodeToString(content), "size": info.Size()})
}

func (a *Agent) fileStat(w http.ResponseWriter, r *http.Request, s *Server) {
	in, _ := readInput(r)
	missing := map[string]any{"exists": false, "dir": false, "size": 0, "mtime": 0, "sha1": nil}
	j, err := jail.Open(s.Dir())
	if err != nil {
		writeJSON(w, 200, missing)
		return
	}
	defer j.Close()
	_, info, err := j.Existing(in.str("path"), true)
	if err != nil {
		if jail.Status(err) == 404 {
			writeJSON(w, 200, missing)
			return
		}
		jailFail(w, err, "")
		return
	}
	reply := map[string]any{"exists": true, "dir": info.IsDir(), "size": 0, "mtime": info.ModTime().Unix(), "sha1": nil}
	if info.Mode().IsRegular() {
		reply["size"] = info.Size()
		if raw, _, err := j.ReadRegular(in.str("path"), MaxRead); err == nil {
			reply["sha1"] = sha1Hex(raw)
		}
	}
	writeJSON(w, 200, reply)
}

func (a *Agent) fileDelete(w http.ResponseWriter, r *http.Request, s *Server) {
	in, _ := readInput(r)
	p := in.str("path")
	if p == "" {
		invalid(w, "The path field is required.")
		return
	}
	j, err := jail.Open(s.Dir())
	if err != nil {
		writeJSON(w, 200, map[string]any{"deleted": false})
		return
	}
	defer j.Close()
	rel, info, err := j.Existing(p, false)
	if err != nil {
		if jail.Status(err) == 404 {
			writeJSON(w, 200, map[string]any{"deleted": false})
			return
		}
		jailFail(w, err, "")
		return
	}
	if !info.Mode().IsRegular() {
		fail(w, 403, "file_error", "Only files can be deleted this way.")
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": j.Remove(rel) == nil})
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
	disabledDir = regexp.MustCompile(`^[a-z-]{1,32}$`)
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
	j, ok := openJail(w, s, "file_error")
	if !ok {
		return
	}
	defer j.Close()
	reply, err := fmDo(j, in)
	if err != nil {
		jailFail(w, err, "file_error")
		return
	}
	writeJSON(w, 200, reply)
}

func fmDo(j *jail.Jail, in input) (any, error) {
	p := in.str("path")
	if len(p) > 1024 {
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
		return fmList(j, p)
	case "read":
		return fmRead(j, p)
	case "write":
		if p == "" || !in.has("content") {
			return nil, bad("path and content are required.")
		}
		var hash *string
		if h := in.str("hash"); h != "" {
			if len(h) != 40 {
				return nil, bad("The hash must be 40 characters.")
			}
			hash = &h
		}
		h, err := fmWrite(j, p, in.str("content"), hash)
		return map[string]any{"hash": h}, err
	case "create_file":
		if err := needName(); err != nil {
			return nil, err
		}
		rel, err := j.NewPath(p, name)
		if err != nil {
			return nil, err
		}
		f, err := j.Create(rel, 0o660)
		if err != nil {
			return nil, bad("Could not create the file.")
		}
		f.Close()
		return map[string]any{"path": rel}, nil
	case "create_folder":
		if err := needName(); err != nil {
			return nil, err
		}
		rel, err := j.NewPath(p, name)
		if err != nil {
			return nil, err
		}
		if err := j.Mkdir(rel); err != nil {
			return nil, bad("Could not create the folder.")
		}
		return map[string]any{"path": rel}, nil
	case "rename":
		if p == "" {
			return nil, bad("The path field is required.")
		}
		if err := needName(); err != nil {
			return nil, err
		}
		rel, err := fmRename(j, p, name)
		return map[string]any{"path": rel}, err
	case "delete":
		if p == "" {
			return nil, bad("The path field is required.")
		}
		return map[string]any{"ok": true}, fmDelete(j, p)
	case "is_file":
		return map[string]any{"file": isFileIn(j, p)}, nil
	case "is_dir":
		return map[string]any{"dir": isDirIn(j, p)}, nil
	case "mkdir":
		rel, err := j.MkdirAll(p)
		return map[string]any{"path": rel}, err
	case "dirs":
		paths, ok := in.strings("paths")
		if !ok || len(paths) == 0 || len(paths) > 50 {
			return nil, bad("paths (1 - 50) are required.")
		}
		dirs := []string{}
		for _, d := range paths {
			if isDirIn(j, d) {
				dirs = append(dirs, d)
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
		if (fw != "oxide" && fw != "carbon") || (cfgDir != "config" && cfgDir != "configs") || !disabledDir.MatchString(disabled) {
			return nil, bad("framework, config_dir and disabled_dir are required.")
		}
		return map[string]any{"plugins": fmPlugins(j, fw, cfgDir, disabled)}, nil
	}
	return nil, &jail.Error{Status: 400, Message: "Unknown file operation."}
}

func fmList(j *jail.Jail, p string) (any, error) {
	rel, info, err := j.Existing(p, true)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, bad("Not a folder.")
	}
	items, err := j.ReadDir(rel)
	if err != nil {
		return nil, err
	}
	entries := []map[string]any{}
	truncated := false
	for _, item := range items {
		if len(entries) >= MaxList {
			truncated = true
			break
		}
		itemRel := strings.Trim(rel+"/"+item.Name(), "/")
		st, _ := j.Lstat(itemRel)
		isLink := j.IsLink(itemRel)
		isDir := !isLink && item.IsDir()
		kind := "file"
		if isLink {
			kind = "link"
		} else if isDir {
			kind = "dir"
		}
		var size, modified any
		if st != nil {
			if !isDir && !isLink {
				size = st.Size()
			}
			modified = st.ModTime().Unix()
		}
		ext := jail.Ext(item.Name())
		entries = append(entries, map[string]any{
			"name":     item.Name(),
			"path":     itemRel,
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

func fmRead(j *jail.Jail, p string) (any, error) {
	rel, err := jail.Normalise(p)
	if err != nil {
		return nil, err
	}
	if j.IsLink(rel) {
		return nil, bad("Not a file.")
	}
	raw, info, err := j.ReadRegular(rel, MaxEdit)
	if err != nil {
		if jail.Status(err) == 413 {
			return nil, bad("File is too large to edit in the browser. Download it instead.")
		}
		return nil, err
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

func fmWrite(j *jail.Jail, p, content string, expected *string) (string, error) {
	rel, err := jail.Normalise(p)
	if err != nil {
		return "", err
	}
	if !j.IsFile(rel) {
		if _, err := j.Lstat(rel); err != nil {
			return "", err
		}
		return "", bad("Not a file.")
	}
	if !jail.Editable[jail.Ext(rel)] {
		return "", bad("This file type cannot be edited.")
	}
	if len(content) > MaxEdit {
		return "", bad("Content is too large.")
	}
	if !utf8.ValidString(content) || strings.IndexByte(content, 0) >= 0 {
		return "", bad("Content must be UTF-8 text.")
	}
	original, _, err := j.ReadRegular(rel, 4*MaxEdit)
	if err != nil {
		return "", err
	}
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
	if err := j.WriteAtomic(rel, out, 0o660); err != nil {
		return "", err
	}
	return sha1Hex(out), nil
}

func parentOf(rel string) string {
	if d := path.Dir(rel); d != "." {
		return d
	}
	return ""
}

func fmRename(j *jail.Jail, p, name string) (string, error) {
	rel, _, err := j.Existing(p, false)
	if err != nil {
		return "", err
	}
	if rel == "" {
		return "", bad("The server folder itself cannot be renamed.")
	}
	to, err := j.NewPath(parentOf(rel), name)
	if err != nil {
		return "", err
	}
	if err := j.Rename(rel, to); err != nil {
		return "", bad("Rename failed. The file may be in use by the server.")
	}
	return to, nil
}

func fmDelete(j *jail.Jail, p string) error {
	rel, _, err := j.Existing(p, false)
	if err != nil {
		return err
	}
	if rel == "" {
		return bad("The server folder itself cannot be deleted.")
	}
	if err := j.RemoveAll(rel); err != nil {
		return bad("Some items could not be deleted. They may be in use by the server.")
	}
	return nil
}

func isFileIn(j *jail.Jail, p string) bool {
	rel, err := jail.Normalise(p)
	return err == nil && j.IsFile(rel)
}

func isDirIn(j *jail.Jail, p string) bool {
	rel, err := jail.Normalise(p)
	return err == nil && j.IsDir(rel)
}

func fmMove(j *jail.Jail, from, toDir string) (string, error) {
	rel, info, err := j.Existing(from, false)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", bad("Not a file.")
	}
	if _, err := j.MkdirAll(toDir); err != nil {
		return "", err
	}
	target, err := j.NewPath(toDir, path.Base(rel))
	if err != nil {
		return "", err
	}
	if err := j.Rename(rel, target); err != nil {
		return "", bad("Could not move the file. It may be in use - try again.")
	}
	return target, nil
}

func fmPlugins(j *jail.Jail, framework, configDir, disabledFolder string) []map[string]any {
	out := []map[string]any{}
	for _, folder := range []struct {
		name     string
		disabled bool
	}{{"plugins", false}, {disabledFolder, true}} {
		dir := framework + "/" + folder.name
		if !j.IsDir(framework) || !j.IsDir(dir) {
			continue // also a link: IsDir doesn't follow
		}
		items, _ := j.ReadDir(dir)
		for _, item := range items {
			if !item.Type().IsRegular() || path.Ext(item.Name()) != ".cs" {
				continue
			}
			rel := dir + "/" + item.Name()
			f, info, err := j.OpenRegular(rel, -1)
			if err != nil {
				continue
			}
			head := make([]byte, PluginHead)
			n, _ := io.ReadFull(f, head)
			f.Close()
			name := strings.TrimSuffix(item.Name(), ".cs")
			out = append(out, map[string]any{
				"name":       name,
				"disabled":   folder.disabled,
				"head":       base64.StdEncoding.EncodeToString([]byte(infoHead(string(head[:n])))),
				"size":       info.Size(),
				"modified":   info.ModTime().Unix(),
				"has_config": j.IsFile(framework + "/" + configDir + "/" + name + ".json"),
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
	j, ok := openJail(w, s, "file_error")
	if !ok {
		return
	}
	defer j.Close()
	truthy := func(k string) bool { v := r.FormValue(k); return v == "1" || v == "true" }
	dir := r.FormValue("path")
	var err error
	if truthy("create") {
		dir, err = j.MkdirAll(dir)
	} else {
		dir, err = jail.Normalise(dir)
	}
	if err != nil {
		jailFail(w, err, "file_error")
		return
	}
	if !j.IsDir(dir) {
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
		name := path.Base(strings.ReplaceAll(fh.Filename, `\`, "/"))
		if err := jail.ValidName(name); err != nil {
			jailFail(w, err, "file_error")
			return
		}
		if err := jail.NotBlocked(name); err != nil {
			jailFail(w, err, "file_error")
			return
		}
		target := strings.Trim(dir+"/"+name, "/")
		if j.IsLink(target) || j.IsDir(target) {
			fail(w, 422, "file_error", "“"+name+"” is a folder or link and cannot be replaced.")
			return
		}
		if j.IsFile(target) && !overwrite {
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
		target := strings.Trim(dir+"/"+p.name, "/")
		err = j.WriteAtomicFrom(target, src, MaxUpload, 0o660)
		src.Close()
		if err != nil {
			fail(w, 422, "file_error", "Could not store "+p.name+".")
			return
		}
		stored = append(stored, target)
	}
	writeJSON(w, 200, map[string]any{"paths": stored})
}

func (a *Agent) fmDownload(w http.ResponseWriter, r *http.Request, s *Server) {
	j, ok := openJail(w, s, "file_error")
	if !ok {
		return
	}
	defer j.Close()
	f, info, err := j.OpenRegular(r.URL.Query().Get("path"), -1)
	if err != nil {
		if jail.Status(err) == 422 {
			err = bad("Only files can be downloaded.")
		}
		jailFail(w, err, "file_error")
		return
	}
	defer f.Close()
	sendFile(w, f, info.Size(), path.Base(r.URL.Query().Get("path")), "application/octet-stream")
}

// sendFile streams an open file as an attachment (never more than its size when opened).
func sendFile(w http.ResponseWriter, f io.Reader, size int64, name, contentType string) {
	w.Header().Set("Content-Length", itoa(size))
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
	_, _ = io.Copy(w, io.LimitReader(f, size))
}

/* ---------- maps ---------- */

var mapName = regexp.MustCompile(`^map_(\d{3,5})_(\d{1,10})\.png$`)

func (a *Agent) maps(w http.ResponseWriter, r *http.Request, s *Server) {
	out := []map[string]any{}
	if j, err := jail.Open(s.Dir()); err == nil {
		items, _ := j.ReadDir("")
		for _, item := range items {
			if !item.Type().IsRegular() || !mapName.MatchString(item.Name()) {
				continue
			}
			if info, err := j.Lstat(item.Name()); err == nil {
				out = append(out, map[string]any{"name": item.Name(), "size": info.Size(), "mtime": info.ModTime().Unix()})
			}
		}
		j.Close()
	}
	writeJSON(w, 200, map[string]any{"maps": out})
}
