package agent

import (
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strconv"
)

var rconPath = regexp.MustCompile(`^/rcon/([0-9]{4,5})/([^/]+)$`)

var quiet = log.New(io.Discard, "", 0)

// rcon is the secure WebRCON pass-through: wss://<machine>/rcon/<port>/<password> -> Rust's WebRCON on this
// machine's 127.0.0.1 (RCON is never opened to the network). The password is part of the path: nothing here logs
// the address. Only allowed IPs get here (checked in ServeHTTP); Rust checks the password itself.
func (a *Agent) rcon(w http.ResponseWriter, r *http.Request) {
	m := rconPath.FindStringSubmatch(r.URL.EscapedPath())
	port, _ := strconv.Atoi(func() string {
		if m == nil {
			return "0"
		}
		return m[1]
	}())
	if m == nil || port < 1024 || port > 65535 {
		http.NotFound(w, r)
		return
	}
	target := &url.URL{Scheme: "http", Host: "127.0.0.1:" + m[1]}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme, pr.Out.URL.Host = target.Scheme, target.Host
			pr.Out.URL.Path, pr.Out.URL.RawPath = "/"+mustUnescape(m[2]), "/"+m[2]
			pr.Out.Host = target.Host
		},
		ErrorLog:      quiet,
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, "the server's RCON does not answer", http.StatusBadGateway)
		},
	}
	proxy.ServeHTTP(w, r)
}

func mustUnescape(s string) string {
	if v, err := url.PathUnescape(s); err == nil {
		return v
	}
	return s
}
