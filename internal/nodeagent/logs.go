package nodeagent

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"radman/internal/nodelog"
	"radman/internal/proto"
)

// applyLogSettings sets the log level and file retention pushed by the manager (empty/0 = defaults), and
// prunes straight away when the retention changed so a shorter age takes effect without waiting for midnight.
func (a *Agent) applyLogSettings(cfg *proto.SiteConfig) {
	lvl, ok := nodelog.ParseLevel(cfg.LogLevel)
	if !ok {
		lvl = nodelog.DefaultLevel
	}
	oldLvl, oldDays := a.Log.Level(), a.Log.RetentionDays()
	a.Log.SetRetentionDays(cfg.LogRetentionDays)
	if lvl != oldLvl {
		if lvl > oldLvl {
			a.Log.SetLevel(lvl) // raising verbosity: announce at the new level
			a.Log.Infof("log level changed from %s to %s", oldLvl, lvl)
		} else {
			a.Log.Infof("log level changing from %s to %s", oldLvl, lvl) // lowering: say it while it is still visible
			a.Log.SetLevel(lvl)
		}
	}
	if d := a.Log.RetentionDays(); d != oldDays {
		a.Log.Infof("log retention changed from %d to %d day(s)", oldDays, d)
		go a.Log.Prune()
	}
}

// logStats reports the node's logging state to the manager.
func (a *Agent) logStats(st *proto.Stats) {
	st.LogLevel = a.Log.Level().String()
	st.LogRetentionDays = a.Log.RetentionDays()
	st.LogBytes = a.Log.Size()
	st.Features = []string{proto.FeatureLogs}
}

// logPruner deletes log files older than the retention period at startup and then hourly (the logger also
// prunes whenever it starts a new day's file).
func (a *Agent) logPruner(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		a.Log.Prune()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// startLogCollection answers the manager's request for a log bundle. It runs beside the check-in loop so a
// large upload never delays config updates or event delivery, and only one upload runs at a time (the manager
// keeps asking until it has the whole bundle, so a failed attempt is simply retried at the next check-in).
func (a *Agent) startLogCollection(ctx context.Context, id string) {
	if !atomic.CompareAndSwapInt32(&a.collecting, 0, 1) {
		return
	}
	go func() {
		defer atomic.StoreInt32(&a.collecting, 0)
		if err := a.collectLogs(ctx, id); err != nil {
			a.Log.Warnf("log collection %s failed: %v", id, err)
		}
	}()
}

func (a *Agent) collectLogs(ctx context.Context, id string) error {
	a.Log.Infof("collecting logs for the manager (bundle %s)", id)
	f, err := os.CreateTemp(a.Dir, "logbundle-*.tmp")
	if err != nil {
		return a.reportLogError(ctx, id, fmt.Errorf("cannot stage bundle: %w", err))
	}
	defer os.Remove(f.Name())
	defer f.Close()

	host, _ := os.Hostname()
	a.mu.Lock()
	hash := ""
	if a.srv != nil {
		hash = a.srv.Runtime().Hash
	}
	a.mu.Unlock()
	info := fmt.Sprintf("RadMAN node log bundle\ncreated: %s\nhost: %s\nos: %s/%s\nnode version: %s\nuptime: %s\nlog level: %s\nlog retention: %d day(s)\nconfig hash: %.12s\n",
		time.Now().UTC().Format(time.RFC3339), host, runtime.GOOS, runtime.GOARCH, Version, time.Since(a.started).Round(time.Second), a.Log.Level(), a.Log.RetentionDays(), hash)
	if _, err := a.Log.BuildBundle(f, info, proto.MaxLogBundleSize); err != nil {
		return a.reportLogError(ctx, id, fmt.Errorf("cannot build bundle: %w", err))
	}
	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return a.reportLogError(ctx, id, err)
	}
	f.Seek(0, io.SeekStart)

	chunks := int((size + proto.LogChunkBytes - 1) / proto.LogChunkBytes)
	if chunks == 0 {
		chunks = 1
	}
	buf := make([]byte, proto.LogChunkBytes)
	for i := 0; i < chunks; i++ {
		n, err := io.ReadFull(f, buf)
		if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
			return err
		}
		up := &proto.LogUpload{ID: id, Index: i, Final: i == chunks-1, Data: buf[:n]}
		if _, err := a.roundTrip(ctx, true, &proto.Request{Type: "logs", Logs: up}); err != nil {
			return fmt.Errorf("uploading chunk %d/%d: %w", i+1, chunks, err)
		}
	}
	a.Log.Infof("log bundle %s uploaded (%d bytes)", id, size)
	return nil
}

// reportLogError tells the manager the bundle could not be built, so the request does not stay pending forever.
func (a *Agent) reportLogError(ctx context.Context, id string, cause error) error {
	msg := cause.Error()
	if len(msg) > 300 {
		msg = msg[:300]
	}
	if _, err := a.roundTrip(ctx, true, &proto.Request{Type: "logs", Logs: &proto.LogUpload{ID: id, Error: strings.TrimSpace(msg)}}); err != nil {
		return fmt.Errorf("%v (and reporting it failed: %w)", cause, err)
	}
	return cause
}
