package agent

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

var rotatedLog = regexp.MustCompile(`^server-\d{8}-\d{6}(-\d+)?\.log$`)

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// MaxChunk is read per poll by default (256 KB); MaxLogRead is the most one call may ask for.
const (
	MaxChunk   = 262144
	MaxLogRead = 1048576
)

var (
	ansi       = regexp.MustCompile(`\x1b\[[\d;]*[A-Za-z]|[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]`)
	rconSecret = regexp.MustCompile(`(?i)(rcon\.password[\s":=]+)[^\s"]+`)
	lineBreak  = regexp.MustCompile(`\r?\n`)
)

// maskSecrets: Rust logs its full command line at startup ("+rcon.password" "secret") - never pass it on.
func maskSecrets(line string) string {
	if strings.Contains(strings.ToLower(line), "rcon.password") {
		line = rconSecret.ReplaceAllString(line, "${1}********")
	}
	return line
}

// tail is the panel's LogTail::read: complete lines after offset, at most maxBytes (older lines are skipped then).
// A file that got shorter (a new server session) starts over with reset = true.
func tail(path string, offset, maxBytes int64) map[string]any {
	reply := func(lines []string, off int64, reset bool) map[string]any {
		if lines == nil {
			lines = []string{}
		}
		return map[string]any{"lines": lines, "offset": off, "reset": reset}
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return reply(nil, 0, offset > 0)
	}
	size := info.Size()
	reset := false
	if offset < 0 || offset > size {
		offset, reset = 0, true
	}
	skipPartial := false
	if size-offset > maxBytes {
		offset, skipPartial = size-maxBytes, true
	}
	if offset == size {
		return reply(nil, offset, reset)
	}
	f, err := os.Open(path)
	if err != nil {
		return reply(nil, offset, reset)
	}
	defer f.Close()
	chunk := make([]byte, size-offset)
	n, err := f.ReadAt(chunk, offset)
	if err != nil && err != io.EOF {
		return reply(nil, offset, reset)
	}
	chunk = chunk[:n]
	last := strings.LastIndexByte(string(chunk), '\n')
	if last < 0 {
		return reply(nil, offset, reset)
	}
	complete := string(chunk[:last+1])
	lines := lineBreak.Split(strings.TrimRight(complete, "\r\n"), -1)
	if skipPartial && len(lines) > 0 {
		lines = lines[1:]
	}
	for i, l := range lines {
		l = ansi.ReplaceAllString(l, "")
		if !utf8.ValidString(l) {
			l = strings.ToValidUTF8(l, "?")
		}
		lines[i] = maskSecrets(l)
	}
	return reply(lines, offset+int64(len(complete)), reset)
}

func fileSize(path string) int64 {
	if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
		return info.Size()
	}
	return 0
}

func (a *Agent) logRead(w http.ResponseWriter, r *http.Request, s *Server) {
	in, _ := readInput(r)
	path := s.LogPath()
	switch in.str("file") {
	case "", "server":
	case "output":
		path = s.OutputPath()
	default:
		invalid(w, "file must be server or output.")
		return
	}
	offset, _ := in.integer("offset")
	maxBytes := int64(MaxChunk)
	if in.has("max") {
		m, ok := in.integer("max")
		if !ok || m < 1024 || m > MaxLogRead {
			invalid(w, "max must be 1024 - 1048576.")
			return
		}
		maxBytes = m
	}
	if offset < 0 {
		invalid(w, "offset must be 0 or more.")
		return
	}
	reply := tail(path, offset, maxBytes)
	reply["size"] = fileSize(path)
	writeJSON(w, 200, reply)
}

func (a *Agent) logDownload(w http.ResponseWriter, r *http.Request, s *Server) {
	f, err := os.Open(s.LogPath())
	if err != nil {
		fail(w, 404, "not_found", "There is no server log yet.")
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+s.Slug+`-server.log"`)
	_, _ = io.Copy(w, f)
}
