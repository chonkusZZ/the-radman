// Command radman-node is the RadMAN site node: a RADIUS (EAP-TLS) server for one site.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/kardianos/service"

	"radman/internal/nodeagent"
)

var version = "dev"

const svcName = "radman-node"

func defaultDataDir() string {
	if v := os.Getenv("RADMAN_DATA"); v != "" {
		return v
	}
	var d string
	switch runtime.GOOS {
	case "windows":
		d = filepath.Join(os.Getenv("ProgramData"), "RadMAN", "node")
	case "darwin":
		d = "/usr/local/var/radman-node"
	default:
		d = "/var/lib/radman-node"
	}
	if err := os.MkdirAll(d, 0o700); err == nil {
		if f, err := os.CreateTemp(d, ".w"); err == nil {
			f.Close()
			os.Remove(f.Name())
			return d
		}
	}
	exe, _ := os.Executable()
	return filepath.Join(filepath.Dir(exe), "radman-node-data")
}

type program struct {
	dir    string
	cancel context.CancelFunc
	done   chan struct{}
	log    *log.Logger
}

func (p *program) Start(service.Service) error {
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel, p.done = cancel, make(chan struct{})
	go func() {
		defer close(p.done)
		nodeagent.Version = version
		if err := nodeagent.New(p.dir, p.log).Run(ctx); err != nil {
			p.log.Printf("fatal: %v", err)
		}
	}()
	return nil
}

func (p *program) Stop(service.Service) error {
	p.cancel()
	<-p.done
	return nil
}

func newLogger(dir string) *log.Logger {
	os.MkdirAll(dir, 0o700)
	path := filepath.Join(dir, "node.log")
	if st, err := os.Stat(path); err == nil && st.Size() > 10<<20 {
		os.Rename(path, path+".1")
	}
	var w io.Writer = os.Stderr
	if f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
		w = io.MultiWriter(os.Stderr, f)
	}
	return log.New(w, "", log.LstdFlags)
}

func usage() {
	fmt.Fprintf(os.Stderr, `radman-node %s

Usage: radman-node [--data-dir DIR] <command>

Commands:
  run        run in the foreground (default)
  install    install as a system service      uninstall   remove the service
  start      start the service                 stop        stop the service
  restart    restart the service               status      show service status
  enroll     --manager HOST:PORT --ca-sha256 FP --token TOKEN   enroll manually
  eaptest    --server HOST:PORT --secret S --cert C --key K --ca CA [--identity ID]
             authenticate once as a test supplicant (diagnostics)
  version
`, version)
}

func main() {
	dataDir := flag.String("data-dir", "", "node data directory")
	flag.Usage = usage
	flag.Parse()
	dir := *dataDir
	if dir == "" {
		dir = defaultDataDir()
	}
	cmd := "run"
	if flag.NArg() > 0 {
		cmd = flag.Arg(0)
	}
	args := flag.Args()
	if len(args) > 0 {
		args = args[1:]
	}

	switch cmd {
	case "version":
		fmt.Println(version)
		return
	case "enroll":
		enroll(dir, args)
		return
	case "eaptest":
		runEAPTest(args)
		return
	case "help", "-h", "--help":
		usage()
		return
	}

	logger := newLogger(dir)
	prg := &program{dir: dir, log: logger}
	svc, err := service.New(prg, &service.Config{
		Name: svcName, DisplayName: "arc's The RadMAN Site Node", Description: "RADIUS EAP-TLS authentication node managed by arc's The RadMAN",
		Arguments: []string{"--data-dir", dir, "run"},
	})
	if err != nil {
		logger.Fatal(err)
	}
	switch cmd {
	case "run":
		if err := svc.Run(); err != nil {
			logger.Fatal(err)
		}
	case "install", "uninstall", "start", "stop", "restart":
		if cmd == "install" {
			lockDownDataDir(dir, logger)
		}
		if err := service.Control(svc, cmd); err != nil {
			logger.Fatalf("%s: %v", cmd, err)
		}
		fmt.Printf("service %s: ok\n", cmd)
	case "status":
		st, err := svc.Status()
		if err != nil {
			logger.Fatal(err)
		}
		fmt.Println(map[service.Status]string{service.StatusRunning: "running", service.StatusStopped: "stopped", service.StatusUnknown: "unknown"}[st])
	default:
		usage()
		os.Exit(2)
	}
}

func enroll(dir string, args []string) {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	mgr := fs.String("manager", "", "manager host:port (UDP)")
	fp := fs.String("ca-sha256", "", "SHA-256 fingerprint of the manager's node CA")
	tok := fs.String("token", "", "enrollment token")
	fs.Parse(args)
	if *mgr == "" || *fp == "" || *tok == "" {
		fs.Usage()
		os.Exit(2)
	}
	os.MkdirAll(dir, 0o700)
	b, _ := json.Marshal(nodeagent.EnrollConfig{Manager: *mgr, CAFP: *fp, Token: *tok})
	if err := os.WriteFile(filepath.Join(dir, "enroll.json"), b, 0o600); err != nil {
		log.Fatal(err)
	}
	a := nodeagent.New(dir, newLogger(dir))
	nodeagent.Version = version
	if err := a.EnrollNow(context.Background()); err != nil {
		os.Remove(filepath.Join(dir, "enroll.json"))
		log.Fatalf("enrollment failed: %v", err)
	}
	fmt.Println("enrolled. Run `radman-node install && radman-node start` to start the service.")
}

// lockDownDataDir restricts the data directory (private keys, AP secrets) to administrators.
// On Unix the files are already 0600 in a 0700 directory; on Windows ProgramData inherits broad read access.
func lockDownDataDir(dir string, l *log.Logger) {
	if runtime.GOOS != "windows" {
		return
	}
	os.MkdirAll(dir, 0o700)
	out, err := exec.Command("icacls", dir, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F").CombinedOutput()
	if err != nil {
		l.Printf("warning: could not restrict permissions on %s: %v: %s", dir, err, out)
	}
}
