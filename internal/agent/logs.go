package agent

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Zand3rsCode/rerust-agent/internal/jail"
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
	ansi = regexp.MustCompile(`\x1b\[[\d;]*[A-Za-z]|[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]`)
	// The value after rcon.password: a quoted one as a whole (it may contain spaces), else up to the next space.
	rconSecret = regexp.MustCompile(`(?i)(rcon\.password["']?[\s:=]+)("[^"]*"|'[^']*'|[^\s"']+)`)
	lineBreak  = regexp.MustCompile(`\r?\n`)
)

// maskSecrets: Rust logs its full command line at startup ("+rcon.password" "secret") - never pass it on.
func maskSecrets(line string) string {
	if strings.Contains(strings.ToLower(line), "rcon.password") {
		line = rconSecret.ReplaceAllString(line, "${1}********")
	}
	return line
}

// tail is the panel's LogTail::read for a file the agent owns (job and update logs).
func tail(path string, offset, maxBytes int64) map[string]any {
	f, err := os.Open(path)
	if err != nil {
		return tailReply(nil, 0, offset > 0)
	}
	defer f.Close()
	return tailFile(f, offset, maxBytes)
}

// tailJail reads a log inside a server folder (the game writes those): through the jail, regular files only.
func tailJail(j *jail.Jail, rel string, offset, maxBytes int64) (map[string]any, int64) {
	f, info, err := j.OpenRegular(rel, -1)
	if err != nil {
		return tailReply(nil, 0, offset > 0), 0
	}
	defer f.Close()
	return tailFile(f, offset, maxBytes), info.Size()
}

func tailReply(lines []string, off int64, reset bool) map[string]any {
	if lines == nil {
		lines = []string{}
	}
	return map[string]any{"lines": lines, "offset": off, "reset": reset}
}

// tailFile: complete lines after offset, at most maxBytes (older lines are skipped then). A file that got shorter
// (a new server session) starts over with reset = true.
func tailFile(f *os.File, offset, maxBytes int64) map[string]any {
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return tailReply(nil, 0, offset > 0)
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
		return tailReply(nil, offset, reset)
	}
	chunk := make([]byte, size-offset)
	n, err := f.ReadAt(chunk, offset)
	if err != nil && err != io.EOF {
		return tailReply(nil, offset, reset)
	}
	chunk = chunk[:n]
	last := strings.LastIndexByte(string(chunk), '\n')
	if last < 0 {
		return tailReply(nil, offset, reset)
	}
	complete := string(chunk[:last+1])
	lines := lineBreak.Split(strings.TrimRight(complete, "\r\n"), -1)
	if skipPartial && len(lines) > 0 {
		lines = lines[1:]
	}
	for i, l := range lines {
		lines[i] = cleanLine(l)
	}
	return tailReply(lines, offset+int64(len(complete)), reset)
}

func cleanLine(l string) string {
	l = ansi.ReplaceAllString(l, "")
	if !utf8.ValidString(l) {
		l = strings.ToValidUTF8(l, "?")
	}
	return maskSecrets(l)
}

func fileSize(path string) int64 {
	if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() {
		return info.Size()
	}
	return 0
}

func (a *Agent) logRead(w http.ResponseWriter, r *http.Request, s *Server) {
	in, _ := readInput(r)
	rel := serverLog
	switch in.str("file") {
	case "", "server":
	case "output":
		rel = outputLog
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
	j, err := jail.Open(s.Dir())
	if err != nil {
		writeJSON(w, 200, map[string]any{"lines": []string{}, "offset": 0, "reset": offset > 0, "size": 0})
		return
	}
	defer j.Close()
	reply, size := tailJail(j, rel, offset, maxBytes)
	reply["size"] = size
	writeJSON(w, 200, reply)
}

// logDownload streams server.log line by line with secrets masked (Rust logs its command line with the RCON
// password).
func (a *Agent) logDownload(w http.ResponseWriter, r *http.Request, s *Server) {
	j, err := jail.Open(s.Dir())
	if err != nil {
		fail(w, 404, "not_found", "There is no server log yet.")
		return
	}
	defer j.Close()
	f, _, err := j.OpenRegular(serverLog, -1)
	if err != nil {
		fail(w, 404, "not_found", "There is no server log yet.")
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+s.Slug+`-server.log"`)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	bw := bufio.NewWriter(w)
	for sc.Scan() {
		_, _ = bw.WriteString(maskSecrets(sc.Text()) + "\n")
	}
	_ = bw.Flush()
}
