// Package nodelog is the site node's leveled, age-pruned logger.
//
// Lines go to stderr (so a foreground run or the service manager still sees them) and to one file per
// day, logs/node-YYYY-MM-DD.log. Files whose last write is older than the configured retention are
// deleted, so retention has whole-file (one day) granularity. Secrets must never be logged, at any level.
package nodelog

import (
	"archive/zip"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Level int32

const (
	Error Level = iota
	Warn
	Info
	Debug
)

const (
	DefaultLevel         = Info
	DefaultRetentionDays = 30
	MaxRetentionDays     = 365

	// maxDayBytes bounds one day's file so a verbose level cannot fill the disk; past it only errors are written.
	maxDayBytes = 100 << 20

	filePrefix = "node-"
	fileSuffix = ".log"
)

var levelNames = [...]string{"error", "warning", "info", "debug"}

func (l Level) String() string {
	if l < Error || l > Debug {
		return "info"
	}
	return levelNames[l]
}

func (l Level) tag() string { return [...]string{"ERROR", "WARN ", "INFO ", "DEBUG"}[l] }

// ParseLevel accepts error, warning (or warn), info and debug, case-insensitively.
func ParseLevel(s string) (Level, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "error":
		return Error, true
	case "warning", "warn":
		return Warn, true
	case "info":
		return Info, true
	case "debug":
		return Debug, true
	}
	return DefaultLevel, false
}

// Logger is safe for concurrent use. The zero value is not usable; use New or Discard.
type Logger struct {
	dir       string
	extra     io.Writer
	level     atomic.Int32
	retention atomic.Int32

	mu      sync.Mutex
	f       *os.File
	day     string
	size    int64
	capped  bool
	now     func() time.Time
	started bool
}

// New logs into dir (created if needed) and to extra (may be nil).
func New(dir string, extra io.Writer) *Logger {
	l := &Logger{dir: dir, extra: extra, now: time.Now}
	l.level.Store(int32(DefaultLevel))
	l.retention.Store(DefaultRetentionDays)
	return l
}

// Discard returns a logger that writes nowhere (tests).
func Discard() *Logger { return New("", nil) }

func (l *Logger) Dir() string { return l.dir }

func (l *Logger) SetLevel(v Level) { l.level.Store(int32(v)) }
func (l *Logger) Level() Level     { return Level(l.level.Load()) }

// SetRetentionDays clamps to 1..MaxRetentionDays; anything else falls back to the default.
func (l *Logger) SetRetentionDays(n int) {
	if n < 1 || n > MaxRetentionDays {
		n = DefaultRetentionDays
	}
	l.retention.Store(int32(n))
}
func (l *Logger) RetentionDays() int { return int(l.retention.Load()) }

func (l *Logger) Errorf(f string, a ...any) { l.logf(Error, f, a...) }
func (l *Logger) Warnf(f string, a ...any)  { l.logf(Warn, f, a...) }
func (l *Logger) Infof(f string, a ...any)  { l.logf(Info, f, a...) }
func (l *Logger) Debugf(f string, a ...any) { l.logf(Debug, f, a...) }

// Printf logs at info level (kept so the stdlib-logger style call sites keep working).
func (l *Logger) Printf(f string, a ...any) { l.logf(Info, f, a...) }

// Enabled reports whether a line at v would be written; lets callers skip building expensive debug arguments.
func (l *Logger) Enabled(v Level) bool { return v <= l.Level() }

// Std returns a *log.Logger that writes at warning level, for libraries that insist on one.
func (l *Logger) Std() *log.Logger { return log.New(levelWriter{l, Warn}, "", 0) }

type levelWriter struct {
	l *Logger
	v Level
}

func (w levelWriter) Write(p []byte) (int, error) {
	w.l.logf(w.v, "%s", strings.TrimRight(string(p), "\r\n"))
	return len(p), nil
}

func (l *Logger) logf(v Level, f string, a ...any) {
	if !l.Enabled(v) {
		return
	}
	t := l.now()
	line := fmt.Sprintf("%s %s %s\n", t.Format("2006-01-02T15:04:05.000Z07:00"), v.tag(), strings.TrimRight(fmt.Sprintf(f, a...), "\r\n"))
	if l.extra != nil {
		io.WriteString(l.extra, line)
	}
	if l.dir == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	day := t.Format("2006-01-02")
	if l.f == nil || day != l.day {
		l.rotateLocked(day, t)
	}
	if l.f == nil {
		return
	}
	if l.size >= maxDayBytes {
		if v != Error {
			if !l.capped {
				l.capped = true
				l.f.WriteString(t.Format("2006-01-02T15:04:05.000Z07:00") + " WARN  daily log size limit reached; only errors are written until midnight\n")
			}
			return
		}
	}
	n, _ := l.f.WriteString(line)
	l.size += int64(n)
}

func (l *Logger) rotateLocked(day string, t time.Time) {
	if l.f != nil {
		l.f.Close()
		l.f = nil
	}
	if err := os.MkdirAll(l.dir, 0o700); err != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(l.dir, filePrefix+day+fileSuffix), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	st, _ := f.Stat()
	l.f, l.day, l.capped = f, day, false
	l.size = 0
	if st != nil {
		l.size = st.Size()
	}
	if l.started { // the first file of a run is pruned by the caller at startup
		go l.Prune()
	}
	l.started = true
}

// Close flushes and closes the current file.
func (l *Logger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f != nil {
		l.f.Close()
		l.f = nil
	}
}

// Files lists the log files, oldest first.
func (l *Logger) Files() []File {
	if l.dir == "" {
		return nil
	}
	ents, err := os.ReadDir(l.dir)
	if err != nil {
		return nil
	}
	var out []File
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || !strings.HasPrefix(n, filePrefix) || !strings.HasSuffix(n, fileSuffix) {
			continue
		}
		if st, err := e.Info(); err == nil {
			out = append(out, File{Name: n, Path: filepath.Join(l.dir, n), Size: st.Size(), ModTime: st.ModTime()})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

type File struct {
	Name    string
	Path    string
	Size    int64
	ModTime time.Time
}

// Size is the number of bytes of log files on disk.
func (l *Logger) Size() (n int64) {
	for _, f := range l.Files() {
		n += f.Size
	}
	return n
}

// Prune deletes log files last written more than the retention period ago and returns how many it removed.
func (l *Logger) Prune() int {
	cutoff := l.now().Add(-time.Duration(l.RetentionDays()) * 24 * time.Hour)
	removed := 0
	l.mu.Lock()
	cur := l.day
	l.mu.Unlock()
	for _, f := range l.Files() {
		if f.Name == filePrefix+cur+fileSuffix {
			continue
		}
		if f.ModTime.Before(cutoff) && os.Remove(f.Path) == nil {
			removed++
		}
	}
	if removed > 0 {
		l.Debugf("log pruning removed %d file(s) older than %d day(s)", removed, l.RetentionDays())
	}
	return removed
}

// BuildBundle writes a zip of the log files plus the given info text to w, newest files first, stopping
// before the zip's compressed size would exceed maxBytes. It returns the names it left out.
func (l *Logger) BuildBundle(w io.Writer, info string, maxBytes int64) (omitted []string, err error) {
	files := l.Files()
	cw := &countWriter{w: w}
	zw := zip.NewWriter(cw)
	add := func(name string, mod time.Time, src io.Reader) error {
		h := &zip.FileHeader{Name: name, Method: zip.Deflate, Modified: mod}
		fw, err := zw.CreateHeader(h)
		if err != nil {
			return err
		}
		_, err = io.Copy(fw, src)
		return err
	}
	var included []string
	for i := len(files) - 1; i >= 0; i-- { // newest first
		f := files[i]
		if cw.n+4096 > maxBytes {
			omitted = append(omitted, f.Name)
			continue
		}
		src, err := os.Open(f.Path)
		if err != nil {
			omitted = append(omitted, f.Name)
			continue
		}
		err = add("logs/"+f.Name, f.ModTime, &limitedByCompressed{r: src, cw: cw, max: maxBytes - 4096})
		src.Close()
		if err == errBundleFull {
			omitted = append(omitted, f.Name+" (truncated)")
			included = append(included, f.Name+" (truncated)")
			continue
		} else if err != nil {
			return omitted, err
		}
		included = append(included, f.Name)
	}
	var sb strings.Builder
	sb.WriteString(info)
	sb.WriteString("\nincluded:\n")
	for _, n := range included {
		sb.WriteString("  " + n + "\n")
	}
	if len(omitted) > 0 {
		sb.WriteString("\nomitted because the bundle size limit was reached:\n")
		for _, n := range omitted {
			sb.WriteString("  " + n + "\n")
		}
	}
	if err := add("info.txt", l.now(), strings.NewReader(sb.String())); err != nil {
		return omitted, err
	}
	return omitted, zw.Close()
}

var errBundleFull = fmt.Errorf("bundle size limit reached")

type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// limitedByCompressed stops a file's copy once the zip written so far reaches the cap (the compressed
// bytes lag the source slightly, so this is approximate, which is fine for a cap).
type limitedByCompressed struct {
	r   io.Reader
	cw  *countWriter
	max int64
}

func (l *limitedByCompressed) Read(p []byte) (int, error) {
	if l.cw.n >= l.max {
		return 0, errBundleFull
	}
	return l.r.Read(p)
}
