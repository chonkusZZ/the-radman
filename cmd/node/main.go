// Command radman-node is the RadMAN site node: a RADIUS (EAP-TLS) server for one site.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/kardianos/service"

	"radman/internal/nodeagent"
	"radman/internal/nodelog"
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
	log    *nodelog.Logger
}

func (p *program) Start(service.Service) error {
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel, p.done = cancel, make(chan struct{})
	go func() {
		defer close(p.done)
		nodeagent.Version = version
		if err := nodeagent.New(p.dir, p.log).Run(ctx); err != nil {
			p.log.Errorf("fatal: %v", err)
		}
	}()
	return nil
}

func (p *program) Stop(service.Service) error {
	p.cancel()
	<-p.done
	return nil
}

// newLogger opens the node's leveled, age-pruned log (logs/node-YYYY-MM-DD.log under the data directory).
// The level and retention are set from the manager's node settings once the config is applied.
func newLogger(dir string) *nodelog.Logger {
	adoptLegacyLogs(dir)
	l := nodelog.New(filepath.Join(dir, "logs"), os.Stderr)
	l.Prune()
	return l
}

// adoptLegacyLogs moves the single-file logs of older node versions into the new log directory so
// retention applies to them too.
func adoptLegacyLogs(dir string) {
	for old, name := range map[string]string{"node.log": "node-legacy.log", "node.log.1": "node-legacy-1.log"} {
		if _, err := os.Stat(filepath.Join(dir, old)); err != nil {
			continue
		}
		if os.MkdirAll(filepath.Join(dir, "logs"), 0o700) == nil {
			os.Rename(filepath.Join(dir, old), filepath.Join(dir, "logs", name))
		}
	}
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
		Name: svcName, DisplayName: "The RadMAN Site Node", Description: "RADIUS EAP-TLS authentication node managed by The RadMAN",
		Arguments: []string{"--data-dir", dir, "run"},
	})
	if err != nil {
		fatal(logger, err)
	}
	switch cmd {
	case "run":
		if err := svc.Run(); err != nil {
			fatal(logger, err)
		}
	case "install", "uninstall", "start", "stop", "restart":
		if cmd == "install" {
			lockDownDataDir(dir, logger)
		}
		if err := service.Control(svc, cmd); err != nil {
			fatal(logger, fmt.Errorf("%s: %w", cmd, err))
		}
		fmt.Printf("service %s: ok\n", cmd)
	case "status":
		st, err := svc.Status()
		if err != nil {
			fatal(logger, err)
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
func lockDownDataDir(dir string, l *nodelog.Logger) {
	if runtime.GOOS != "windows" {
		return
	}
	os.MkdirAll(dir, 0o700)
	out, err := exec.Command("icacls", dir, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F").CombinedOutput()
	if err != nil {
		l.Warnf("could not restrict permissions on %s: %v: %s", dir, err, out)
	}
}

func fatal(l *nodelog.Logger, err error) {
	l.Errorf("fatal: %v", err)
	os.Exit(1)
}
