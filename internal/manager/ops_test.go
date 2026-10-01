package manager

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestEventPartitionsAndRetention(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	w := newWorldFor(t, a)
	insert := func(seq int, ts time.Time) {
		if _, err := a.St.DB.Exec(ctx, `INSERT INTO events(node_id,site_id,tenant_id,seq,ts,kind,data) VALUES($1::uuid,$2::uuid,$3::uuid,$4,$5,'auth','{}')`, w.node, w.site, w.tenant, seq, ts); err != nil {
			t.Fatal(err)
		}
	}
	insert(1, time.Now())
	// current + next two months exist, so live inserts never hit the default partition
	var n int
	a.St.DB.QueryRow(ctx, `SELECT count(*) FROM pg_inherits i JOIN pg_class p ON p.oid=i.inhparent WHERE p.relname='events'`).Scan(&n)
	if n < 4 { // 3 months + default
		t.Fatalf("expected >=4 partitions, got %d", n)
	}
	// duplicate delivery (a node retrying after a lost ack) is ignored
	if _, err := a.St.DB.Exec(ctx, `INSERT INTO events(node_id,site_id,tenant_id,seq,ts,kind,data) VALUES($1::uuid,$2::uuid,$3::uuid,1,(SELECT ts FROM events WHERE seq=1),'auth','{}') ON CONFLICT (node_id, seq, ts) DO NOTHING`, w.node, w.site, w.tenant); err != nil {
		t.Fatal(err)
	}
	a.St.DB.QueryRow(ctx, `SELECT count(*) FROM events WHERE seq=1`).Scan(&n)
	if n != 1 {
		t.Fatalf("duplicate event stored: %d", n)
	}

	// an old month: create its partition, add data, then retention (90 days) drops the whole partition
	old := monthStart(time.Now().AddDate(0, -6, 0))
	a.St.DB.Exec(ctx, fmt.Sprintf(`CREATE TABLE %s PARTITION OF events FOR VALUES FROM ('%s') TO ('%s')`, partName(old), old.Format("2006-01-02"), old.AddDate(0, 1, 0).Format("2006-01-02")))
	insert(2, old.AddDate(0, 0, 3))
	insert(3, time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC)) // clock-skewed node -> default partition
	dropped, err := a.dropOldPartitions(ctx, 90)
	if err != nil || len(dropped) != 1 || dropped[0] != partName(old) {
		t.Fatalf("dropped %v err %v", dropped, err)
	}
	a.St.DB.QueryRow(ctx, `SELECT count(*) FROM events`).Scan(&n)
	if n != 1 {
		t.Fatalf("after retention only the recent event should remain, got %d", n)
	}
}

type miniWorld struct{ tenant, site, node string }

func newWorldFor(t *testing.T, a *App) *miniWorld {
	ctx := context.Background()
	tn, _ := a.CreateTenant(ctx, "Ops")
	w := &miniWorld{tenant: tn.ID}
	eap, _ := a.CreateInternalEAPCert(ctx, tn.ID, "s", "s.test", nil)
	a.St.DB.QueryRow(ctx, `INSERT INTO sites(tenant_id,name,eap_cert_id) VALUES($1::uuid,'s',$2::uuid) RETURNING id::text`, tn.ID, eap).Scan(&w.site)
	a.St.DB.QueryRow(ctx, `INSERT INTO nodes(site_id,name) VALUES($1::uuid,'n') RETURNING id::text`, w.site).Scan(&w.node)
	return w
}

func TestRunExclusiveAllowsOneInstance(t *testing.T) {
	a := testApp(t)
	ctx := context.Background()
	inside := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		a.runExclusive(ctx, 4242, func(context.Context) { close(inside); <-release })
		close(done)
	}()
	<-inside
	ran := false
	a.runExclusive(ctx, 4242, func(context.Context) { ran = true }) // a second "instance" must skip
	if ran {
		t.Fatal("the job ran twice concurrently")
	}
	close(release)
	<-done
	a.runExclusive(ctx, 4242, func(context.Context) { ran = true })
	if !ran {
		t.Fatal("lock was not released")
	}
}

func TestKeyKitRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	kit, err := SealKeyKit(key, "a long passphrase!")
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenKeyKit(kit, "a long passphrase!")
	if err != nil || string(got) != string(key) {
		t.Fatalf("round trip failed: %v", err)
	}
	if _, err := OpenKeyKit(kit, "wrong passphrase!!"); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	if _, err := SealKeyKit(key, "short"); err == nil {
		t.Fatal("short passphrase accepted")
	}
}
