// rerust-agent runs Rust dedicated servers on this machine for a ReRust panel.
//
//	rerust-agent serve      the agent (systemd starts this)
//	rerust-agent pair       make a pairing code for the panel (Settings -> Machines -> Add machine)
//	rerust-agent version
package main

import (
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"syscall"
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
	cmd := "serve"
	args := os.Args[1:]
	if len(args) > 0 && args[0][0] != '-' {
		cmd, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	cfgPath := fs.String("config", config.DefaultPath, "config file")
	_ = fs.Parse(args)

	switch cmd {
	case "version":
		fmt.Println(version)
	case "serve":
		serve(*cfgPath)
	case "pair":
		pair(*cfgPath)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q (serve, pair, version)\n", cmd)
		os.Exit(2)
	}
}

func load(path string) config.Config {
	cfg, err := config.Load(path)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if err := os.MkdirAll(cfg.StateDir, 0o750); err != nil {
		log.Fatalf("state folder: %v", err)
	}
	return cfg
}

func serve(path string) {
	log.SetFlags(0)
	cfg := load(path)
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
	a, err := agent.New(version, cfg, store, stats)
	if err != nil {
		log.Fatalf("agent: %v", err)
	}
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           a,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}},
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       2 * time.Minute,
		// No read/write timeout: backups stream for minutes and RCON websockets stay open.
		ErrorLog: log.New(os.Stderr, "", 0),
	}
	if !store.Paired() {
		log.Printf("Not paired with a panel yet - run: sudo rerust-agent pair")
	}
	log.Printf("ReRust Agent v%s listening on %s (servers in %s)", version, cfg.Listen, cfg.BaseDir)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

// pair prints a pairing code: "rra1." + the certificate's sha256 + "." + a one-time secret. The panel checks the
// certificate against it, so the code only works with this machine.
func pair(path string) {
	cfg := load(path)
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
	secret, err := store.NewPairing()
	if err != nil {
		log.Fatalf("pairing: %v", err)
	}
	chownLikeStateDir(cfg.StateDir, cfg.StateDir+"/auth.json", files.Cert, files.Key, cfg.StateDir+"/tls")
	fmt.Printf("rra1.%s.%s\n", base64.RawURLEncoding.EncodeToString(fp), secret)
	fmt.Fprintf(os.Stderr, "Paste this pairing code into the panel (Settings -> Machines -> Add machine) within %d hours. It works once.\n", auth.PairHours)
}

// chownLikeStateDir: `pair` runs as root; the files must stay readable for the agent's own user.
func chownLikeStateDir(stateDir string, paths ...string) {
	info, err := os.Stat(stateDir)
	if err != nil {
		return
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || os.Geteuid() != 0 {
		return
	}
	for _, p := range paths {
		_ = os.Chown(p, int(st.Uid), int(st.Gid))
	}
}
