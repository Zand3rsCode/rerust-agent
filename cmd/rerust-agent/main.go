// rerust-agent runs Rust dedicated servers on this machine for a ReRust panel.
//
//	rerust-agent serve              the agent (systemd starts it; its port comes from rerust-agent.socket)
//	rerust-agent pair [--replace]   make a pairing code for the panel (as the agent's user, never root)
//	rerust-agent launch --dir D     inside rerust-server@<slug>.service: start that server's RustDedicated
//	rerust-agent install-update     rerust-agent-update.service (root): install a downloaded, signed release
//	rerust-agent version
package main

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/Zand3rsCode/rerust-agent/internal/agent"
	"github.com/Zand3rsCode/rerust-agent/internal/auth"
	"github.com/Zand3rsCode/rerust-agent/internal/config"
	"github.com/Zand3rsCode/rerust-agent/internal/sysstats"
	"github.com/Zand3rsCode/rerust-agent/internal/tlscert"
)

// version is set at build time (-ldflags "-X main.version=1.2.3").
var version = "0.0.0-dev"

func main() {
	log.SetFlags(0)
	cmd := "serve"
	args := os.Args[1:]
	if len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		cmd, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	cfgPath := fs.String("config", config.DefaultPath, "config file")
	replace := fs.Bool("replace", false, "pair: replace the panel this machine is paired with")
	dir := fs.String("dir", "", "launch: the server folder")
	_ = fs.Parse(args)

	switch cmd {
	case "version":
		fmt.Println(version)
	case "serve":
		serve(*cfgPath)
	case "pair":
		pair(*cfgPath, *replace)
	case "launch":
		if err := agent.Launch(*dir); err != nil {
			log.Fatalf("launch: %v", err)
		}
	case "install-update":
		cfg := load(*cfgPath, false)
		if err := agent.InstallUpdate(cfg.StateDir, version); err != nil {
			log.Fatalf("update: %v", err)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q (serve, pair, launch, install-update, version)\n", cmd)
		os.Exit(2)
	}
}

func load(path string, makeState bool) config.Config {
	cfg, err := config.Load(path)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if makeState {
		if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
			log.Fatalf("state folder: %v", err)
		}
	}
	return cfg
}

// listener: the socket systemd opened for us (rerust-agent.socket - so the agent needs no capability for its port,
// even 443), else listen itself (development).
func listener(addr string) (net.Listener, error) {
	if os.Getenv("LISTEN_PID") == strconv.Itoa(os.Getpid()) && os.Getenv("LISTEN_FDS") != "" {
		n, _ := strconv.Atoi(os.Getenv("LISTEN_FDS"))
		if n < 1 {
			return nil, errors.New("systemd passed no socket")
		}
		f := os.NewFile(3, "rerust-agent.socket")
		l, err := net.FileListener(f) // dups the socket close-on-exec
		f.Close()
		os.Unsetenv("LISTEN_PID")
		os.Unsetenv("LISTEN_FDS")
		os.Unsetenv("LISTEN_FDNAMES")
		return l, err
	}
	return net.Listen("tcp", addr)
}

// errRoot: serve and pair never run as root (SECURITY.md A3) - they work on files the agent's user owns.
var errRoot = errors.New("not as root")

func notRoot(euid int) error {
	if euid == 0 {
		return errRoot
	}
	return nil
}

func serve(path string) {
	if notRoot(os.Geteuid()) != nil {
		log.Fatal("the agent never runs as root - systemd starts it as its own user")
	}
	cfg := load(path, true)
	files := tlscert.In(cfg.StateDir)
	if err := tlscert.Ensure(files); err != nil {
		log.Fatalf("certificate: %v", err)
	}
	cert, err := tlscert.Load(files)
	if err != nil {
		log.Fatalf("certificate: %v", err)
	}
	store, err := auth.Open(cfg.StateDir + "/auth.json")
	if err != nil {
		log.Fatalf("auth.json: %v", err)
	}
	stats := &sysstats.Sampler{}
	go stats.Run(make(chan struct{}))
	a, err := agent.New(version, cfg, store, stats, nil)
	if err != nil {
		log.Fatalf("agent: %v", err)
	}
	l, err := listener(cfg.Listen)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	srv := &http.Server{
		Handler:           a,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}},
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
		// No read/write timeout: backups stream for minutes and RCON websockets stay open.
		ErrorLog: log.New(os.Stderr, "", 0),
	}
	if !store.Paired() {
		log.Printf("Not paired with a panel yet - run: sudo -u rerust-agent /opt/rerust-agent/rerust-agent pair")
	}
	log.Printf("ReRust Agent v%s listening on %s (servers in %s)", version, l.Addr(), cfg.BaseDir)
	log.Fatal(srv.ServeTLS(l, "", ""))
}

// pair prints a pairing code: "rra1." + the certificate's sha256 + "." + a one-time secret. The panel checks the
// certificate against it, so the code only works with this machine. Never as root: it would work on files the
// agent's user owns (links planted there could make root change system files).
func pair(path string, replace bool) {
	if notRoot(os.Geteuid()) != nil {
		log.Fatal("don't run this as root - run: sudo -u rerust-agent /opt/rerust-agent/rerust-agent pair")
	}
	cfg := load(path, true)
	files := tlscert.In(cfg.StateDir)
	if err := tlscert.Ensure(files); err != nil {
		log.Fatalf("certificate: %v", err)
	}
	fp, err := tlscert.Fingerprint(files)
	if err != nil {
		log.Fatalf("certificate: %v", err)
	}
	store, err := auth.Open(cfg.StateDir + "/auth.json")
	if err != nil {
		log.Fatalf("auth.json: %v", err)
	}
	secret, err := store.NewPairing(replace)
	if err != nil {
		log.Fatalf("pairing: %v", err)
	}
	fmt.Printf("rra1.%s.%s\n", base64.RawURLEncoding.EncodeToString(fp), secret)
	fmt.Fprintf(os.Stderr, "Paste this pairing code into the panel (Settings -> Machines -> Add machine) within %d minutes. It works once.\n", auth.PairMinutes)
}
