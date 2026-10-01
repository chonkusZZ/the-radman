package nodeagent

import "testing"

func TestQueuePersistsAndAcks(t *testing.T) {
	dir := t.TempDir()
	q, err := OpenQueue(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		q.Add("auth", map[string]string{"n": string(rune('a' + i))})
	}
	q.Ack(3)
	if q.Len() != 2 {
		t.Fatalf("len %d", q.Len())
	}
	// restart: remaining events and sequence numbers survive, seq never reused
	q2, err := OpenQueue(dir)
	if err != nil {
		t.Fatal(err)
	}
	ev := q2.Peek(10)
	if len(ev) != 2 || ev[0].Seq != 4 || ev[1].Seq != 5 {
		t.Fatalf("after restart: %+v", ev)
	}
	q2.Ack(5)
	q3, _ := OpenQueue(dir)
	q3.Add("acct", nil)
	if got := q3.Peek(1)[0].Seq; got != 6 {
		t.Fatalf("sequence reused after full ack: %d", got)
	}
}
