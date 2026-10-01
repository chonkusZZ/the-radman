package nodeagent

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"radman/internal/proto"
)

const maxQueue = 200000

// Queue is a durable FIFO of events awaiting upload to the manager.
type Queue struct {
	mu      sync.Mutex
	dir     string
	events  []proto.Event
	nextSeq uint64
	f       *os.File
}

func OpenQueue(dir string) (*Queue, error) {
	q := &Queue{dir: dir, nextSeq: 1}
	if b, err := os.ReadFile(filepath.Join(dir, "seq")); err == nil {
		if n, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64); err == nil {
			q.nextSeq = n
		}
	}
	if f, err := os.Open(filepath.Join(dir, "events.jsonl")); err == nil {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			var e proto.Event
			if json.Unmarshal(sc.Bytes(), &e) == nil {
				q.events = append(q.events, e)
				if e.Seq >= q.nextSeq {
					q.nextSeq = e.Seq + 1
				}
			}
		}
		f.Close()
	}
	f, err := os.OpenFile(filepath.Join(dir, "events.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	q.f = f
	return q, nil
}

func (q *Queue) Add(kind string, data map[string]string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	e := proto.Event{Seq: q.nextSeq, Time: time.Now().UTC(), Kind: kind, Data: data}
	q.nextSeq++
	q.events = append(q.events, e)
	b, _ := json.Marshal(e)
	q.f.Write(append(b, '\n'))
	if len(q.events) > maxQueue {
		q.events = q.events[len(q.events)-maxQueue/2:]
		q.rewriteLocked()
	}
}

func (q *Queue) Peek(n int) []proto.Event {
	q.mu.Lock()
	defer q.mu.Unlock()
	if n > len(q.events) {
		n = len(q.events)
	}
	return append([]proto.Event(nil), q.events[:n]...)
}

func (q *Queue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.events)
}

// Ack drops all events with seq <= acked.
func (q *Queue) Ack(acked uint64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	i := 0
	for i < len(q.events) && q.events[i].Seq <= acked {
		i++
	}
	if i == 0 {
		return
	}
	q.events = q.events[i:]
	q.rewriteLocked()
}

func (q *Queue) rewriteLocked() {
	tmp := filepath.Join(q.dir, "events.jsonl.tmp")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	w := bufio.NewWriter(f)
	for _, e := range q.events {
		b, _ := json.Marshal(e)
		w.Write(append(b, '\n'))
	}
	w.Flush()
	f.Close()
	q.f.Close()
	os.Rename(tmp, filepath.Join(q.dir, "events.jsonl"))
	q.f, _ = os.OpenFile(filepath.Join(q.dir, "events.jsonl"), os.O_APPEND|os.O_WRONLY, 0o600)
	os.WriteFile(filepath.Join(q.dir, "seq"), []byte(strconv.FormatUint(q.nextSeq, 10)), 0o600)
}
