package nodelog

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func readAll(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func todayFile(l *Logger) string {
	return filepath.Join(l.Dir(), filePrefix+l.now().Format("2006-01-02")+fileSuffix)
}

func TestParseLevel(t *testing.T) {
	for in, want := range map[string]Level{"error": Error, "WARNING": Warn, " warn ": Warn, "Info": Info, "debug": Debug} {
		if got, ok := ParseLevel(in); !ok || got != want {
			t.Errorf("ParseLevel(%q) = %v,%v want %v", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "trace", "fatal", "3"} {
		if got, ok := ParseLevel(in); ok || got != DefaultLevel {
			t.Errorf("ParseLevel(%q) = %v,%v, want default and !ok", in, got, ok)
		}
	}
	if Warn.String() != "warning" || Level(99).String() != "info" {
		t.Error("level names")
	}
}

func TestLevelFiltering(t *testing.T) {
	var console bytes.Buffer
	l := New(t.TempDir(), &console)
	emit := func() {
		l.Errorf("e-line")
		l.Warnf("w-line")
		l.Infof("i-line")
		l.Debugf("d-line")
	}
	for _, c := range []struct {
		level Level
		want  []string
		not   []string
	}{
		{Error, []string{"e-line"}, []string{"w-line", "i-line", "d-line"}},
		{Warn, []string{"e-line", "w-line"}, []string{"i-line", "d-line"}},
		{Info, []string{"e-line", "w-line", "i-line"}, []string{"d-line"}},
		{Debug, []string{"e-line", "w-line", "i-line", "d-line"}, nil},
	} {
		console.Reset()
		os.Remove(todayFile(l))
		l.Close()
		l.SetLevel(c.level)
		emit()
		file := readAll(t, todayFile(l))
		for name, out := range map[string]string{"file": file, "console": console.String()} {
			for _, w := range c.want {
				if !strings.Contains(out, w) {
					t.Errorf("level %s: %s lacks %q", c.level, name, w)
				}
			}
			for _, n := range c.not {
				if strings.Contains(out, n) {
					t.Errorf("level %s: %s contains %q", c.level, name, n)
				}
			}
		}
	}
	if l.Enabled(Debug) != true || New("", nil).Enabled(Debug) != false {
		t.Error("Enabled() does not follow the level")
	}
}

func TestStdLoggerWritesWarnings(t *testing.T) {
	l := New(t.TempDir(), nil)
	l.SetLevel(Warn)
	l.Std().Printf("library complaint")
	if !strings.Contains(readAll(t, todayFile(l)), "WARN  library complaint") {
		t.Error("Std() output not logged at warning level")
	}
	l.SetLevel(Error)
	l.Std().Printf("hidden")
	if strings.Contains(readAll(t, todayFile(l)), "hidden") {
		t.Error("Std() output logged although level is error")
	}
}

func TestRetentionClamp(t *testing.T) {
	l := New("", nil)
	for in, want := range map[int]int{0: DefaultRetentionDays, -3: DefaultRetentionDays, 1: 1, 90: 90, MaxRetentionDays: MaxRetentionDays, MaxRetentionDays + 1: DefaultRetentionDays} {
		l.SetRetentionDays(in)
		if got := l.RetentionDays(); got != want {
			t.Errorf("SetRetentionDays(%d) -> %d, want %d", in, got, want)
		}
	}
}

// writeAged creates a log file whose last write was `age` ago.
func writeAged(t *testing.T, l *Logger, name string, age time.Duration) string {
	t.Helper()
	os.MkdirAll(l.Dir(), 0o700)
	p := filepath.Join(l.Dir(), name)
	if err := os.WriteFile(p, []byte("line from "+name+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	when := l.now().Add(-age)
	if err := os.Chtimes(p, when, when); err != nil {
		t.Fatal(err)
	}
	return p
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func TestPruneDeletesOnlyOlderThanRetention(t *testing.T) {
	l := New(t.TempDir(), nil)
	l.SetRetentionDays(7)
	day := 24 * time.Hour
	old := writeAged(t, l, "node-2020-01-01.log", 400*day)
	justOver := writeAged(t, l, "node-2020-02-01.log", 7*day+time.Hour)
	justUnder := writeAged(t, l, "node-2020-03-01.log", 7*day-time.Hour)
	fresh := writeAged(t, l, "node-2020-04-01.log", time.Hour)
	other := filepath.Join(l.Dir(), "notes.txt") // not ours: never touched
	os.WriteFile(other, []byte("x"), 0o600)
	os.Chtimes(other, l.now().Add(-900*day), l.now().Add(-900*day))

	if n := l.Prune(); n != 2 {
		t.Fatalf("pruned %d files, want 2", n)
	}
	if exists(old) || exists(justOver) {
		t.Error("files older than the age were kept")
	}
	if !exists(justUnder) || !exists(fresh) {
		t.Error("files inside the age were deleted")
	}
	if !exists(other) {
		t.Error("a file that is not a node log was deleted")
	}

	// shortening the age deletes more; lengthening never resurrects
	l.SetRetentionDays(1)
	if n := l.Prune(); n != 1 || exists(justUnder) || !exists(fresh) {
		t.Errorf("after shortening to 1 day: pruned=%d justUnder=%v fresh=%v", n, exists(justUnder), exists(fresh))
	}
}

func TestPruneNeverDeletesTheFileBeingWritten(t *testing.T) {
	l := New(t.TempDir(), nil)
	l.SetRetentionDays(1)
	l.Infof("today")
	cur := todayFile(l)
	past := l.now().Add(-72 * time.Hour)
	os.Chtimes(cur, past, past) // clock skew / odd mtime: still today's open file
	l.Prune()
	if !exists(cur) {
		t.Fatal("pruning removed the log file in use")
	}
}

func TestDayRollOverCreatesNewFileAndPrunes(t *testing.T) {
	l := New(t.TempDir(), nil)
	l.SetRetentionDays(2)
	clock := time.Date(2026, 5, 10, 23, 59, 0, 0, time.UTC)
	l.now = func() time.Time { return clock }
	old := writeAged(t, l, "node-2026-05-01.log", 9*24*time.Hour)
	l.Infof("before midnight")
	clock = clock.Add(2 * time.Minute)
	l.Infof("after midnight")
	if !exists(filepath.Join(l.Dir(), "node-2026-05-10.log")) || !exists(filepath.Join(l.Dir(), "node-2026-05-11.log")) {
		t.Fatal("expected one file per day")
	}
	deadline := time.Now().Add(2 * time.Second) // rollover prunes in the background
	for exists(old) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if exists(old) {
		t.Error("rollover did not prune files older than the age")
	}
}

func TestDailySizeCapKeepsErrors(t *testing.T) {
	l := New(t.TempDir(), nil)
	l.Infof("start")
	l.size = maxDayBytes // pretend the day's file is full
	l.Infof("dropped-info")
	l.Errorf("kept-error")
	got := readAll(t, todayFile(l))
	if strings.Contains(got, "dropped-info") || !strings.Contains(got, "kept-error") || !strings.Contains(got, "size limit reached") {
		t.Errorf("size cap behaviour wrong:\n%s", got)
	}
}

func unzip(t *testing.T, b []byte) map[string]string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatalf("bundle is not a zip: %v", err)
	}
	out := map[string]string{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		data, _ := io.ReadAll(rc)
		rc.Close()
		out[f.Name] = string(data)
	}
	return out
}

func TestBuildBundle(t *testing.T) {
	l := New(t.TempDir(), nil)
	writeAged(t, l, "node-2026-05-01.log", 3*24*time.Hour)
	writeAged(t, l, "node-2026-05-02.log", 2*24*time.Hour)
	writeAged(t, l, "stray.log", time.Hour) // not a node log: not collected
	var buf bytes.Buffer
	omitted, err := l.BuildBundle(&buf, "host: test\n", 1<<20)
	if err != nil || len(omitted) != 0 {
		t.Fatalf("BuildBundle: omitted=%v err=%v", omitted, err)
	}
	files := unzip(t, buf.Bytes())
	if len(files) != 3 || files["logs/node-2026-05-01.log"] == "" || files["logs/node-2026-05-02.log"] == "" {
		t.Errorf("unexpected bundle contents: %v", keys(files))
	}
	if !strings.Contains(files["info.txt"], "host: test") || !strings.Contains(files["info.txt"], "node-2026-05-02.log") {
		t.Errorf("info.txt: %q", files["info.txt"])
	}
	for name := range files {
		if strings.Contains(name, "stray") || strings.Contains(name, "..") || strings.HasPrefix(name, "/") {
			t.Errorf("bad entry name %q", name)
		}
	}
}

func TestBuildBundleRespectsSizeLimit(t *testing.T) {
	l := New(t.TempDir(), nil)
	// incompressible data so the compressed size is close to the raw size
	big := make([]byte, 300<<10)
	x := uint32(1)
	for i := range big {
		x = x*1664525 + 1013904223
		big[i] = byte(x >> 24)
	}
	os.MkdirAll(l.Dir(), 0o700)
	for _, n := range []string{"node-2026-05-01.log", "node-2026-05-02.log", "node-2026-05-03.log"} {
		os.WriteFile(filepath.Join(l.Dir(), n), big, 0o600)
	}
	var buf bytes.Buffer
	omitted, err := l.BuildBundle(&buf, "i\n", 400<<10)
	if err != nil {
		t.Fatal(err)
	}
	if buf.Len() > 450<<10 {
		t.Errorf("bundle is %d bytes, limit was %d", buf.Len(), 400<<10)
	}
	if len(omitted) == 0 {
		t.Error("expected some files to be omitted")
	}
	files := unzip(t, buf.Bytes())
	if _, ok := files["logs/node-2026-05-03.log"]; !ok {
		t.Error("newest file must be included first")
	}
	if !strings.Contains(files["info.txt"], "omitted") {
		t.Error("info.txt does not list what was left out")
	}
}

func keys(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
