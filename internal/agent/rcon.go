package agent

import (
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var rconPath = regexp.MustCompile(`^/rcon/([0-9]{4,5})/([^/]+)$`)

var quiet = log.New(io.Discard, "", 0)

// rcon is the secure WebRCON pass-through: wss://<machine>/rcon/<port>/<password> -> Rust's WebRCON on this
// machine's 127.0.0.1 (RCON is never opened to the network). Only with the machine key (checked in ServeHTTP), only
// to the RCON port of a server registered here, and only as a websocket - never a way to any other local service.
// The password is part of the path: nothing here logs the address. The key is not passed on to Rust.
func (a *Agent) rcon(w http.ResponseWriter, r *http.Request) {
	m := rconPath.FindStringSubmatch(r.URL.EscapedPath())
	port := 0
	if m != nil {
		port, _ = strconv.Atoi(m[1])
	}
	if m == nil || !a.servers.rconPorts()[port] {
		fail(w, 404, "not_found", "No server here uses that RCON port.")
		return
	}
	if r.Method != http.MethodGet || !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		fail(w, 400, "bad_request", "RCON is a websocket.")
		return
	}
	target := &url.URL{Scheme: "http", Host: "127.0.0.1:" + m[1]}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme, pr.Out.URL.Host = target.Scheme, target.Host
			pr.Out.URL.Path, pr.Out.URL.RawPath = "/"+mustUnescape(m[2]), "/"+m[2]
			pr.Out.URL.RawQuery = ""
			pr.Out.Host = target.Host
			pr.Out.Header.Del("Authorization")
			pr.Out.Header.Del("Cookie")
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
