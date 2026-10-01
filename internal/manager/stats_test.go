package manager

import (
	"context"
	"encoding/csv"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"radman/internal/proto"
)

func TestStatsHelpers(t *testing.T) {
	for in, want := range map[string]string{"F6-08-AB-9A-8D-E6": "f6:08:ab:9a:8d:e6", "f6:08:ab:9a:8d:e6": "f6:08:ab:9a:8d:e6", " AA-BB-CC-DD-EE-FF ": "aa:bb:cc:dd:ee:ff",
		"": "", "nonsense": "", "aa-bb-cc-dd-ee": "", "gg:bb:cc:dd:ee:ff": ""} {
		if got := normMAC(in); got != want {
			t.Errorf("normMAC(%q)=%q want %q", in, got, want)
		}
	}
	// locally administered bit = bit 1 of the first octet
	if !isPrivateMAC("f6:08:ab:9a:8d:e6") || isPrivateMAC("f4:08:ab:9a:8d:e6") || !isPrivateMAC("02:00:00:00:00:01") {
		t.Error("private MAC detection")
	}
	if ssidOf("76-22-32-2C-50-EF:Oak Lodge EAP") != "Oak Lodge EAP" || ssidOf("nocolon") != "" {
		t.Error("ssidOf")
	}
	for reason, want := range map[string]string{
		"Cust PKI: certificate serial 1001 revoked at 2026-10-01T18:25:55Z": "Revoked certificate",
		"x509: certificate has expired or is not yet valid: current time":   "Expired certificate",
		"CRL for \"CA\" is stale (expired 2026-01-01, fail-closed)":         "Revocation list unavailable",
		"no CRL available for issuer":                                       "Revocation list unavailable",
		"denied by rule block-phones":                                       "Denied by policy",
		"no rule matched (default deny)":                                    "Denied by policy",
		"x509: certificate signed by unknown authority":                     "Untrusted certificate authority",
		"remote error: tls: unknown certificate authority":                  "Client aborted TLS (often distrusts the server certificate)",
		"tls: client didn't provide a certificate":                          "No client certificate",
		"": "other", "something else entirely": "Other",
	} {
		if got := ReasonCategory(reason); got != want {
			t.Errorf("ReasonCategory(%q)=%q want %q", reason, got, want)
		}
	}
}

type statWorld struct {
	a      *App
	ctx    context.Context
	tenant string
	site   string
	node   string
	seq    uint64
}

func newStatWorld(t *testing.T, a *App, name string) *statWorld {
	ctx := context.Background()
	tn, err := a.CreateTenant(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	w := &statWorld{a: a, ctx: ctx, tenant: tn.ID}
	eap, _ := a.CreateInternalEAPCert(ctx, tn.ID, "srv", "srv."+strings.ToLower(name)+".test", nil)
	a.St.DB.QueryRow(ctx, `INSERT INTO sites(tenant_id,name,eap_cert_id) VALUES($1::uuid,'HQ',$2::uuid) RETURNING id::text`, tn.ID, eap).Scan(&w.site)
	a.St.DB.QueryRow(ctx, `INSERT INTO nodes(site_id,name,status) VALUES($1::uuid,'n','active') RETURNING id::text`, w.site).Scan(&w.node)
	return w
}

func (w *statWorld) ident() *nodeIdentity {
	return &nodeIdentity{ID: w.node, SiteID: w.site, TenantID: w.tenant}
}

func (w *statWorld) ev(at time.Time, kind string, data map[string]string) proto.Event {
	w.seq++
	return proto.Event{Seq: w.seq, Time: at, Kind: kind, Data: data}
}

func auth(result, mac, ap, subject, reason string) map[string]string {
	return map[string]string{"result": result, "client_mac": mac, "ap": ap, "subject": subject, "reason": reason, "ssid": "00-11-22-33-44-55:Corp"}
}

func acct(status, mac, ap, sid string, in, out, ging, goutg int64, secs int64) map[string]string {
	return map[string]string{"status": status, "client_mac": mac, "ap": ap, "session_id": sid, "in_octets": fmt.Sprint(in), "out_octets": fmt.Sprint(out),
		"in_gigawords": fmt.Sprint(ging), "out_gigawords": fmt.Sprint(goutg), "session_time": fmt.Sprint(secs), "ssid": "00-11-22-33-44-55:Corp"}
}

// roamScenario is the same sequence used to check live ingestion and the backfill.
func roamScenario(w *statWorld, base time.Time) []proto.Event {
	const A, B = "F6-08-AB-9A-8D-E6", "02-00-00-00-00-02"
	return []proto.Event{
		w.ev(base, "auth", auth("accept", A, "AP1", "laptop-1", "")),
		w.ev(base.Add(10*time.Minute), "acct", acct("Start", "f6:08:ab:9a:8d:e6", "AP1", "s1", 0, 0, 0, 0, 0)), // same AP: no roam
		w.ev(base.Add(20*time.Minute), "auth", auth("accept", A, "AP2", "laptop-1", "")),                       // roam 1
		w.ev(base.Add(3*time.Hour), "auth", auth("accept", A, "AP2", "laptop-1", "")),
		w.ev(base.Add(3*time.Hour+5*time.Minute), "auth", auth("accept", A, "AP3", "laptop-1", "")), // roam 2
		w.ev(base.Add(5*time.Hour), "auth", auth("accept", A, "AP1", "laptop-1", "")),               // AP changed but >1h later: not a roam
		w.ev(base.Add(time.Minute), "auth", auth("reject", B, "AP1", "", "remote error: tls: unknown certificate authority")),
		w.ev(base.Add(2*time.Minute), "auth", auth("reject", B, "AP1", "", "denied by rule x")),
	}
}

type clientSnap struct {
	First, Last                       time.Time
	Accepts, Rejects, Sessions, Roams int64
	LastAP, Subject                   string
}

func (w *statWorld) clients(t *testing.T) map[string]clientSnap {
	rows, err := w.a.St.DB.Query(w.ctx, `SELECT mac, first_seen, last_seen, accepts, rejects, sessions, roams, last_ap, last_subject FROM client_stats WHERE tenant_id=$1::uuid`, w.tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]clientSnap{}
	for rows.Next() {
		var mac string
		var c clientSnap
		rows.Scan(&mac, &c.First, &c.Last, &c.Accepts, &c.Rejects, &c.Sessions, &c.Roams, &c.LastAP, &c.Subject)
		c.First, c.Last = c.First.UTC(), c.Last.UTC()
		out[mac] = c
	}
	return out
}

func (w *statWorld) hourly(t *testing.T) map[string]string {
	out := map[string]string{}
	rows, _ := w.a.St.DB.Query(w.ctx, `SELECT to_char(hour AT TIME ZONE 'UTC','YYYY-MM-DD HH24'), accepts, rejects FROM stats_hourly WHERE tenant_id=$1::uuid`, w.tenant)
	for rows.Next() {
		var h string
		var a, r int64
		rows.Scan(&h, &a, &r)
		out[h] = fmt.Sprintf("%d/%d", a, r)
	}
	rows.Close()
	rr, _ := w.a.St.DB.Query(w.ctx, `SELECT to_char(hour AT TIME ZONE 'UTC','YYYY-MM-DD HH24')||' '||category, n FROM stats_reasons WHERE tenant_id=$1::uuid`, w.tenant)
	for rr.Next() {
		var k string
		var n int64
		rr.Scan(&k, &n)
		out[k] = fmt.Sprint(n)
	}
	rr.Close()
	return out
}

func TestStatsIngestRoamsAndIdempotency(t *testing.T) {
	a := testApp(t)
	w := newStatWorld(t, a, "Stats Co")
	base := time.Now().UTC().Truncate(time.Hour).Add(-8 * time.Hour)
	evs := roamScenario(w, base)

	if _, err := a.storeEvents(w.ctx, w.ident(), evs); err != nil {
		t.Fatal(err)
	}
	c := w.clients(t)
	aa, bb := c["f6:08:ab:9a:8d:e6"], c["02:00:00:00:00:02"]
	if aa.Accepts != 5 || aa.Sessions != 1 || aa.Roams != 2 || aa.Rejects != 0 || aa.LastAP != "AP1" || aa.Subject != "laptop-1" {
		t.Errorf("client A: %+v", aa)
	}
	if !aa.First.Equal(base) || !aa.Last.Equal(base.Add(5*time.Hour)) {
		t.Errorf("client A first/last: %v %v", aa.First, aa.Last)
	}
	if bb.Rejects != 2 || bb.Accepts != 0 || bb.Roams != 0 {
		t.Errorf("client B: %+v", bb)
	}
	var aps int
	w.a.St.DB.QueryRow(w.ctx, `SELECT count(*) FROM client_aps WHERE tenant_id=$1::uuid AND mac='f6:08:ab:9a:8d:e6'`, w.tenant).Scan(&aps)
	if aps != 3 {
		t.Errorf("AP history: %d APs", aps)
	}
	h := w.hourly(t)
	snapshot := fmt.Sprint(h)
	if len(h) == 0 {
		t.Fatal("no hourly rollups")
	}
	wantReject := base.Format("2006-01-02 15") + " Client aborted TLS (often distrusts the server certificate)"
	if h[wantReject] != "1" || h[base.Format("2006-01-02 15")+" Denied by policy"] != "1" {
		t.Errorf("reject categories: %v", h)
	}

	// a retried batch (lost ack) must not be counted again
	if _, err := a.storeEvents(w.ctx, w.ident(), evs); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(w.hourly(t)) != snapshot || w.clients(t)["f6:08:ab:9a:8d:e6"] != aa {
		t.Error("duplicate delivery changed the statistics")
	}
	var n int
	a.St.DB.QueryRow(w.ctx, `SELECT count(*) FROM events WHERE tenant_id=$1::uuid`, w.tenant).Scan(&n)
	if n != len(evs) {
		t.Errorf("duplicate events stored: %d", n)
	}

	// arrival order inside a batch must not matter
	w2 := newStatWorld(t, a, "Shuffled Co")
	rev := roamScenario(w2, base)
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	if _, err := a.storeEvents(w2.ctx, w2.ident(), rev); err != nil {
		t.Fatal(err)
	}
	if got := w2.clients(t)["f6:08:ab:9a:8d:e6"]; got != aa {
		t.Errorf("reversed delivery gives %+v, want %+v", got, aa)
	}
}

// The backfill replays stored events through the same code, so history built after an upgrade equals what live ingestion produces.
func TestStatsBackfillMatchesLive(t *testing.T) {
	a := testApp(t)
	live := newStatWorld(t, a, "Live Co")
	raw := newStatWorld(t, a, "Raw Co")
	base := time.Now().UTC().Truncate(time.Hour).Add(-8 * time.Hour)
	if _, err := a.storeEvents(live.ctx, live.ident(), roamScenario(live, base)); err != nil {
		t.Fatal(err)
	}
	// "raw" tenant: events exist but were stored before statistics did
	for _, e := range roamScenario(raw, base) {
		a.St.DB.Exec(raw.ctx, `INSERT INTO events(node_id,site_id,tenant_id,seq,ts,kind,data) VALUES($1::uuid,$2::uuid,$3::uuid,$4,$5,$6,$7)`, raw.node, raw.site, raw.tenant, e.Seq, e.Time, e.Kind, jsonOf(e.Data))
	}
	wantClients, wantHourly := live.clients(t), live.hourly(t)

	for _, q := range []string{`DELETE FROM client_aps`, `DELETE FROM client_stats`, `DELETE FROM stats_reasons`, `DELETE FROM stats_hourly`, `DELETE FROM settings WHERE key='stats_backfilled'`} {
		a.St.DB.Exec(live.ctx, q)
	}
	if err := a.backfillStats(live.ctx); err != nil {
		t.Fatal(err)
	}
	for name, sw := range map[string]*statWorld{"live tenant": live, "raw tenant": raw} {
		gotC, gotH := sw.clients(t), sw.hourly(t)
		for mac, want := range wantClients {
			g := gotC[mac]
			if g.Accepts != want.Accepts || g.Rejects != want.Rejects || g.Sessions != want.Sessions || g.Roams != want.Roams || g.LastAP != want.LastAP || !g.First.Equal(want.First) || !g.Last.Equal(want.Last) {
				t.Errorf("%s client %s: backfill %+v, live %+v", name, mac, g, want)
			}
		}
		if len(gotH) != len(wantHourly) {
			t.Errorf("%s hourly rollups: %v vs %v", name, gotH, wantHourly)
		}
	}
	// running it again does nothing (flag set)
	before := fmt.Sprint(live.hourly(t))
	a.backfillStats(live.ctx)
	if fmt.Sprint(live.hourly(t)) != before {
		t.Error("backfill ran twice")
	}
}

func TestStatsSeriesBucketsAndTimezones(t *testing.T) {
	a := testApp(t)
	w := newStatWorld(t, a, "Series Co")
	s := &server{a: a}
	now := time.Now().UTC()
	put := func(at time.Time, acc, rej int64) {
		a.St.DB.Exec(w.ctx, `INSERT INTO stats_hourly(tenant_id,site_id,hour,accepts,rejects) VALUES($1::uuid,$2::uuid,$3,$4,$5)
			ON CONFLICT (tenant_id,site_id,hour) DO UPDATE SET accepts=stats_hourly.accepts+EXCLUDED.accepts, rejects=stats_hourly.rejects+EXCLUDED.rejects`, w.tenant, w.site, at.Truncate(time.Hour), acc, rej)
	}
	put(now.Add(-2*time.Hour), 10, 1)
	put(now.Add(-26*time.Hour), 5, 2)
	put(now.Add(-40*24*time.Hour), 100, 100) // outside the 30-day window
	for _, c := range []struct {
		unit    string
		buckets int
	}{{"hour", 48}, {"day", 30}, {"month", 12}} {
		ser, err := s.statsSeries(w.ctx, w.tenant, "", "UTC", periods[c.unit])
		if err != nil {
			t.Fatal(err)
		}
		if len(ser.Labels) != c.buckets {
			t.Errorf("%s: %d buckets, want %d (gaps must be filled with zeros)", c.unit, len(ser.Labels), c.buckets)
		}
		if c.unit != "month" && (ser.TotalA != 15 || ser.TotalR != 3) {
			t.Errorf("%s totals %d/%d", c.unit, ser.TotalA, ser.TotalR)
		}
	}
	// the day boundary follows the viewing time zone: 23:30 UTC yesterday is already "today" in Auckland (UTC+12/+13)
	at := time.Date(now.Year(), now.Month(), now.Day(), 23, 30, 0, 0, time.UTC).AddDate(0, 0, -1)
	put(at, 77, 0)
	lastBucket := func(tz string) string {
		ser, err := s.statsSeries(w.ctx, w.tenant, "", tz, periods["day"])
		if err != nil {
			t.Fatal(err)
		}
		for i := len(ser.Labels) - 1; i >= 0; i-- {
			if ser.Accepts[i] >= 77 { // only the bucket holding the 77 (others are <= 15)
				return ser.Labels[i]
			}
		}
		return ""
	}
	utcLabel, nzLabel := lastBucket("UTC"), lastBucket("Pacific/Auckland")
	if utcLabel == "" || nzLabel == "" || utcLabel == nzLabel {
		t.Errorf("time zone must move the event to a different day bucket: UTC=%q Auckland=%q", utcLabel, nzLabel)
	}
	// a site filter narrows; an unknown site id shows nothing
	ser, _ := s.statsSeries(w.ctx, w.tenant, "00000000-0000-0000-0000-000000000000", "UTC", periods["day"])
	if ser.TotalA != 0 {
		t.Error("filter by a site with no data should be empty")
	}
}

func TestStatsPagesReportsAndIsolation(t *testing.T) {
	w := newWorld(t)
	A, B := "Alpha", "Bravo"
	base := time.Now().UTC().Add(-3 * time.Hour)
	mk := func(tenant string) *statWorld {
		return &statWorld{a: w.a, ctx: w.ctx, tenant: w.tenant[tenant].ID, site: w.site[tenant], node: w.node[tenant]}
	}
	sa, sb := mk(A), mk(B)
	// Alpha: one client, two sessions of data (second above 4 GB via gigawords), one rejected unknown, one hostile subject
	evA := []proto.Event{
		sa.ev(base, "auth", auth("accept", "aa-aa-aa-aa-aa-01", "Lobby", "laptop-a", "")),
		sa.ev(base.Add(time.Minute), "acct", acct("Start", "aa-aa-aa-aa-aa-01", "Lobby", "s1", 0, 0, 0, 0, 0)),
		sa.ev(base.Add(10*time.Minute), "acct", acct("Interim-Update", "aa-aa-aa-aa-aa-01", "Lobby", "s1", 1000, 2000, 0, 0, 600)),
		sa.ev(base.Add(20*time.Minute), "acct", acct("Stop", "aa-aa-aa-aa-aa-01", "Lobby", "s1", 3000, 5000, 2, 1, 1200)), // 2 and 1 gigawords
		sa.ev(base.Add(30*time.Minute), "acct", acct("Start", "aa-aa-aa-aa-aa-02", "Hall", "s2", 0, 0, 0, 0, 0)),
		sa.ev(base.Add(40*time.Minute), "acct", acct("Stop", "aa-aa-aa-aa-aa-02", "Hall", "s2", 700, 900, 0, 0, 300)),
		sa.ev(base.Add(50*time.Minute), "auth", auth("reject", "aa-aa-aa-aa-aa-03", "Hall", "=HYPERLINK(\"http://evil\")", "tls: client didn't provide a certificate")),
	}
	evB := []proto.Event{sb.ev(base, "auth", auth("accept", "bb-bb-bb-bb-bb-01", "BravoAP", "laptop-b", "")),
		sb.ev(base.Add(time.Minute), "acct", acct("Stop", "bb-bb-bb-bb-bb-01", "BravoAP", "sx", 9999, 9999, 0, 0, 10))}
	if _, err := w.a.storeEvents(w.ctx, sa.ident(), evA); err != nil {
		t.Fatal(err)
	}
	if _, err := w.a.storeEvents(w.ctx, sb.ident(), evB); err != nil {
		t.Fatal(err)
	}
	aadmin, aro, badmin := w.as(t, "aadmin", A), w.as(t, "aro", A), w.as(t, "badmin", B)

	// every role that can read a tenant can open stats and download reports; strangers cannot
	for _, who := range []*actor{aadmin, aro} {
		for _, p := range []string{"/stats", "/stats?range=hour", "/stats?range=month&tz=Europe/London", "/stats/clients", "/stats/clients/aa:aa:aa:aa:aa:01", "/stats/clients/AA-AA-AA-AA-AA-01", "/stats/reports",
			"/stats/report/ap-usage", "/stats/report/top-talkers?format=csv", "/stats/report/rejects?format=csv&preset=24h", "/stats/report/clients?format=csv"} {
			code, _ := who.do(t, "GET", p, nil)
			expect(t, "GET "+p, code, 200)
		}
	}
	code, page := aadmin.do(t, "GET", "/stats?range=hour", nil)
	if code != 200 || !strings.Contains(page, "<svg") || !strings.Contains(page, "Accepted") {
		t.Error("overview should render SVG charts")
	}
	if strings.Contains(page, "bb:bb:bb") {
		t.Error("overview leaks another tenant's clients")
	}
	// isolation
	_, clients := aadmin.do(t, "GET", "/stats/clients", nil)
	if !strings.Contains(clients, "aa:aa:aa:aa:aa:01") || strings.Contains(clients, "bb:bb:bb:bb:bb:01") {
		t.Error("client list must contain exactly the tenant's own clients")
	}
	code, _ = aadmin.do(t, "GET", "/stats/clients/bb:bb:bb:bb:bb:01", nil)
	expect(t, "other tenant's client", code, 404)
	code, _ = aadmin.do(t, "GET", "/stats/clients/not-a-mac", nil)
	expect(t, "malformed client id", code, 404)
	_, rep := aadmin.do(t, "GET", "/stats/report/ap-usage?format=csv&site="+w.site[B], nil) // foreign site id is ignored
	if strings.Contains(rep, "BravoAP") {
		t.Error("report leaked another tenant's access point")
	}
	_, rep = badmin.do(t, "GET", "/stats/report/top-talkers?format=csv", nil)
	if strings.Contains(rep, "aa:aa:aa") || !strings.Contains(rep, "bb:bb:bb:bb:bb:01") {
		t.Error("tenant B's report must show only tenant B")
	}

	// ---- report numbers ----
	read := func(path string) [][]string {
		_, body := aadmin.do(t, "GET", path, nil)
		body = strings.TrimPrefix(body, "\xef\xbb\xbf")
		rows, err := csv.NewReader(strings.NewReader(body)).ReadAll()
		if err != nil {
			t.Fatalf("%s: not valid CSV: %v\n%s", path, err, body)
		}
		return rows
	}
	const gig = 4294967296
	tt := read("/stats/report/top-talkers?format=csv")
	// header, then client 01 first (≈ 8.6 GB up + 4.3 GB down), 02 second
	if len(tt) != 3 || tt[1][1] != "aa:aa:aa:aa:aa:01" || tt[2][1] != "aa:aa:aa:aa:aa:02" {
		t.Fatalf("top talkers: %v", tt)
	}
	if tt[1][4] != fmt.Sprint(3000+2*gig) || tt[1][5] != fmt.Sprint(5000+1*gig) || tt[1][3] != "1" || tt[1][7] != "1200" {
		t.Errorf("client 01 bytes (interim must not double-count, gigawords must be added): %v", tt[1])
	}
	if tt[2][4] != "700" || tt[2][5] != "900" {
		t.Errorf("client 02: %v", tt[2])
	}
	ap := read("/stats/report/ap-usage?format=csv")
	byAP := map[string][]string{}
	for _, r := range ap[1:] {
		byAP[r[1]] = r
	}
	lobby, hall := byAP["Lobby"], byAP["Hall"]
	if lobby == nil || hall == nil || lobby[2] != "1" || lobby[5] != "1" || lobby[8] != fmt.Sprint(8000+3*gig) || hall[3] != "1" || hall[4] != "2" {
		t.Errorf("AP usage: Lobby=%v Hall=%v", lobby, hall)
	}
	if ap[1][1] != "Lobby" {
		t.Error("AP usage should be ordered by total bytes")
	}
	// CSV formula injection is neutralised
	rj := read("/stats/report/rejects?format=csv")
	if len(rj) != 2 || !strings.HasPrefix(rj[1][2], "'=HYPERLINK") || rj[1][5] != "No client certificate" {
		t.Errorf("rejects report: %v", rj)
	}
	// headers and the printable view
	resp, err := aadmin.cl.Get(w.srv.URL + "/stats/report/ap-usage?format=csv")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/csv") || !strings.Contains(resp.Header.Get("Content-Disposition"), "radman-alpha-ap-usage-") {
		t.Errorf("CSV headers: %v", resp.Header)
	}
	_, html := aadmin.do(t, "GET", "/stats/report/ap-usage", nil)
	if !strings.Contains(html, "Access point usage") || !strings.Contains(html, "GB") || strings.Contains(html, "8589") {
		i := strings.Index(html, "<table")
		t.Errorf("printable view should show human-readable sizes: %s", html[i:min(len(html), i+900)])
	}
	// the HTML view must not rename columns for later requests (regression: shared column slice)
	_, csvAgain := aadmin.do(t, "GET", "/stats/report/ap-usage?format=csv", nil)
	if !strings.Contains(csvAgain, "Upload bytes (from clients)") {
		t.Error("CSV header changed after an HTML view")
	}
	// retention clamp is announced
	w.a.St.SetJSON(w.ctx, "general", General{EventRetentionDays: 5, NodeIntervalSecs: 60, Timezone: "UTC", PublicHost: "127.0.0.1"})
	w.a.mu.Lock()
	w.a.gen = nil
	w.a.mu.Unlock()
	_, html = aadmin.do(t, "GET", "/stats/report/rejects?preset=90d", nil)
	if !strings.Contains(html, "Detailed events are kept for 5 days") {
		t.Error("report should say it was clamped to the event retention")
	}
	// client detail: roam badge and AP history
	_, det := aadmin.do(t, "GET", "/stats/clients/aa:aa:aa:aa:aa:01", nil)
	if !strings.Contains(det, "Lobby") || !strings.Contains(det, "laptop-a") {
		t.Error("client detail incomplete")
	}
	// unauthenticated users are sent to sign in
	anon := w.as(t, "aro", A)
	anon.cl.Jar = nil
	r, _ := anon.cl.Get(w.srv.URL + "/stats")
	r.Body.Close()
	expect(t, "anonymous /stats", r.StatusCode, 303)
}

func TestStatsPurge(t *testing.T) {
	a := testApp(t)
	w := newStatWorld(t, a, "Purge Co")
	old, recent := time.Now().AddDate(0, 0, -500), time.Now().AddDate(0, 0, -5)
	for _, ts := range []time.Time{old, recent} {
		a.St.DB.Exec(w.ctx, `INSERT INTO stats_hourly(tenant_id,site_id,hour,accepts) VALUES($1::uuid,$2::uuid,$3,1)`, w.tenant, w.site, ts.Truncate(time.Hour))
	}
	a.St.DB.Exec(w.ctx, `INSERT INTO client_stats(tenant_id,mac,first_seen,last_seen) VALUES($1::uuid,'aa:aa:aa:aa:aa:aa',$2,$2),($1::uuid,'bb:bb:bb:bb:bb:bb',$3,$3)`, w.tenant, old, recent)
	a.purgeStats(w.ctx, 400)
	var h, c int
	a.St.DB.QueryRow(w.ctx, `SELECT count(*) FROM stats_hourly WHERE tenant_id=$1::uuid`, w.tenant).Scan(&h)
	a.St.DB.QueryRow(w.ctx, `SELECT count(*) FROM client_stats WHERE tenant_id=$1::uuid`, w.tenant).Scan(&c)
	if h != 1 || c != 1 {
		t.Errorf("after purge: %d hourly rows, %d clients", h, c)
	}
}

func TestStatsStandaloneAndDeletion(t *testing.T) {
	w := newSoloWorld(t)
	sw := &statWorld{a: w.a, ctx: w.ctx, tenant: w.a.solo.ID}
	a := w.a
	a.St.DB.QueryRow(w.ctx, `INSERT INTO sites(tenant_id,name) VALUES($1::uuid,'HQ') RETURNING id::text`, sw.tenant).Scan(&sw.site)
	a.St.DB.QueryRow(w.ctx, `INSERT INTO nodes(site_id,name,status) VALUES($1::uuid,'n','active') RETURNING id::text`, sw.site).Scan(&sw.node)
	a.storeEvents(w.ctx, sw.ident(), []proto.Event{sw.ev(time.Now().Add(-time.Hour), "auth", auth("accept", "cc-cc-cc-cc-cc-01", "AP", "dev", ""))})
	for _, who := range []string{"admin", "operator", "viewer"} {
		for _, p := range []string{"/stats", "/stats/clients", "/stats/reports", "/stats/report/clients?format=csv"} {
			code, body := w.as(t, who, "").do(t, "GET", p, nil)
			expect(t, who+" GET "+p, code, 200)
			if p == "/stats/clients" && !strings.Contains(body, "cc:cc:cc:cc:cc:01") {
				t.Errorf("%s: client missing", who)
			}
		}
	}
	code, _ := w.as(t, "stranger", "").do(t, "GET", "/stats", nil)
	expect(t, "stranger /stats", code, 403)
	// deleting a tenant removes its statistics (MSP behaviour, at the data layer)
	tn, _ := a.CreateTenant(w.ctx, "Doomed")
	d := newStatWorldFor(t, a, tn)
	a.storeEvents(d.ctx, d.ident(), []proto.Event{d.ev(time.Now(), "auth", auth("reject", "dd-dd-dd-dd-dd-01", "AP", "", "revoked"))})
	if err := a.DeleteTenant(w.ctx, tn.ID); err != nil {
		t.Fatal(err)
	}
	var n int
	a.St.DB.QueryRow(w.ctx, `SELECT (SELECT count(*) FROM client_stats WHERE tenant_id=$1::uuid)+(SELECT count(*) FROM stats_hourly WHERE tenant_id=$1::uuid)+(SELECT count(*) FROM stats_reasons WHERE tenant_id=$1::uuid)+(SELECT count(*) FROM client_aps WHERE tenant_id=$1::uuid)`, tn.ID).Scan(&n)
	if n != 0 {
		t.Errorf("tenant deletion left %d statistics rows", n)
	}
	_ = url.Values{}
}

func newStatWorldFor(t *testing.T, a *App, tn *Tenant) *statWorld {
	ctx := context.Background()
	w := &statWorld{a: a, ctx: ctx, tenant: tn.ID}
	a.St.DB.QueryRow(ctx, `INSERT INTO sites(tenant_id,name) VALUES($1::uuid,'HQ') RETURNING id::text`, tn.ID).Scan(&w.site)
	a.St.DB.QueryRow(ctx, `INSERT INTO nodes(site_id,name,status) VALUES($1::uuid,'n','active') RETURNING id::text`, w.site).Scan(&w.node)
	return w
}

func TestChartAxisIsRound(t *testing.T) {
	for _, c := range []struct{ in, want int64 }{{0, 4}, {3, 4}, {4, 4}, {5, 8}, {37, 40}, {220, 240}, {1234, 1600}, {999999, 1000000}} {
		if got := niceMax(c.in); got != c.want {
			t.Errorf("niceMax(%d)=%d want %d", c.in, got, c.want)
		}
		if got := niceMax(c.in); got%4 != 0 || got < c.in {
			t.Errorf("niceMax(%d)=%d must be >= value and divisible by 4", c.in, got)
		}
	}
	svg := string(stackedBars("x", []string{"a", "b"}, []string{"a: 1", "b: <script>"}, []chartSeries{{"s", "c-ok", []int64{1, 0}}}))
	if strings.Contains(svg, "<script>") || !strings.Contains(svg, "&lt;script&gt;") {
		t.Error("tooltips must be escaped")
	}
	if !strings.Contains(string(stackedBars("x", []string{"a"}, []string{"a"}, []chartSeries{{"s", "c-ok", []int64{0}}})), "No data") {
		t.Error("empty chart should say so")
	}
}
