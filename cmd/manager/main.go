// Command radman-manager runs the RadMAN manager: web UI plus the UDP/QUIC node channel.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	_ "time/tzdata" // time zones for the Stats page even in minimal images

	"radman/internal/manager"
)

var version = "dev"

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	var o manager.Options
	flag.StringVar(&o.DatabaseURL, "database-url", env("RADMAN_DATABASE_URL", env("DATABASE_URL", "")), "PostgreSQL connection URL [RADMAN_DATABASE_URL]")
	flag.StringVar(&o.DatabaseROURL, "database-ro-url", env("RADMAN_DATABASE_RO_URL", ""), "optional PostgreSQL read replica for logs/dashboards [RADMAN_DATABASE_RO_URL]")
	flag.StringVar(&o.DataDir, "data-dir", env("RADMAN_DATA", "./data"), "directory for the master key and ACME cache [RADMAN_DATA]")
	flag.StringVar(&o.HTTPSAddr, "https-addr", env("RADMAN_HTTPS_ADDR", ":8443"), "web UI listen address (use :443 in production) [RADMAN_HTTPS_ADDR]")
	flag.StringVar(&o.HTTPAddr, "http-addr", env("RADMAN_HTTP_ADDR", ""), "optional plain-HTTP address that redirects to HTTPS (e.g. :80) [RADMAN_HTTP_ADDR]")
	flag.StringVar(&o.UDPAddr, "udp-addr", env("RADMAN_UDP_ADDR", ":7843"), "the single UDP port used by site nodes [RADMAN_UDP_ADDR]")
	flag.StringVar(&o.NodeBinDir, "node-bin-dir", env("RADMAN_NODE_BIN_DIR", "./dist/nodes"), "directory containing radman-node_<os>_<arch> binaries [RADMAN_NODE_BIN_DIR]")
	flag.StringVar(&o.Mode, "mode", env("RADMAN_MODE", "msp"), "edition: msp (multi-tenant) or standalone (single organisation) [RADMAN_MODE]")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	o.Version = version
	if o.DatabaseURL == "" {
		log.Fatal("a PostgreSQL URL is required: --database-url postgres://user:pass@host:5432/radman")
	}
	l := log.New(os.Stderr, "radman: ", log.LstdFlags)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	app, err := manager.New(ctx, o, l)
	if err != nil {
		l.Fatal(err)
	}
	if err := app.Run(ctx); err != nil {
		l.Fatal(err)
	}
}
