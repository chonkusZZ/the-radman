package manager

import (
	"context"
	"encoding/csv"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ---- shared helpers ----

// statsLoc returns the viewing time zone (?tz= if valid, else the platform setting).
func (s *server) statsLoc(r *http.Request) (*time.Location, string) {
	name := strings.TrimSpace(r.URL.Query().Get("tz"))
	if name == "" {
		name = s.a.General(r.Context()).Timezone
	}
	if loc, err := time.LoadLocation(name); err == nil && name != "" {
		return loc, name
	}
	return time.UTC, "UTC"
}

// siteFilter validates ?site= against the tenant (a foreign id is simply ignored) and lists the tenant's sites.
func (s *server) siteFilter(r *http.Request, tenantID string) (site string, sites []selOpt) {
	rows, _ := s.a.St.DB.Query(r.Context(), `SELECT id::text, name FROM sites WHERE tenant_id=$1::uuid ORDER BY name`, tenantID)
	want := r.URL.Query().Get("site")
	for rows.Next() {
		var x selOpt
		rows.Scan(&x.ID, &x.Name)
		x.Selected = x.ID == want
		if x.Selected {
			site = x.ID
		}
		sites = append(sites, x)
	}
	rows.Close()
	return
}

func siteArg(site string) any {
	if site == "" {
		return nil
	}
	return site
}

func fmtBytes(n int64) string {
	f := float64(n)
	for _, u := range []string{"B", "KB", "MB", "GB", "TB"} {
		if f < 1024 || u == "TB" {
			if u == "B" {
				return fmt.Sprintf("%d B", n)
			}
			return fmt.Sprintf("%.1f %s", f, u)
		}
		f /= 1024
	}
	return ""
}

func fmtDur(sec int64) string {
	d := time.Duration(sec) * time.Second
	switch {
	case d >= 24*time.Hour:
		return fmt.Sprintf("%dd %dh", int(d.Hours())/24, int(d.Hours())%24)
	case d >= time.Hour:
		return fmt.Sprintf("%dh %02dm", int(d.Hours()), int(d.Minutes())%60)
	case d >= time.Minute:
		return fmt.Sprintf("%dm %02ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%ds", sec)
}

func tfmt(t *time.Time, loc *time.Location) string {
	if t == nil || t.IsZero() {
		return "—"
	}
	return t.In(loc).Format("2006-01-02 15:04")
}

// ---- overview: accepted / rejected graphs ----

type periodSpec struct{ unit, span, step, label, tipFmt, axisFmt string }

var periods = map[string]periodSpec{
	"hour":  {"hour", "47 hours", "1 hour", "Last 48 hours, per hour", "Mon 2 Jan 15:04", "Mon 15:04"},
	"day":   {"day", "29 days", "1 day", "Last 30 days, per day", "Mon 2 Jan 2006", "2 Jan"},
	"month": {"month", "11 months", "1 month", "Last 12 months, per month", "January 2006", "Jan 06"},
}

type statsSeries struct {
	Labels, Tips     []string
	Accepts, Rejects []int64
	TotalA, TotalR   int64
}

func (s *server) statsSeries(ctx context.Context, tenantID, site, tz string, p periodSpec) (*statsSeries, error) {
	rows, err := s.a.St.RO.Query(ctx, `
		WITH p AS (SELECT date_trunc($2, now() AT TIME ZONE $3) AS endb),
		b AS (SELECT generate_series(p.endb - $4::interval, p.endb, $5::interval) AS b FROM p)
		SELECT b.b, COALESCE(sum(h.accepts),0)::bigint, COALESCE(sum(h.rejects),0)::bigint
		FROM b LEFT JOIN stats_hourly h ON h.tenant_id=$1::uuid AND ($6::uuid IS NULL OR h.site_id=$6::uuid)
		  AND h.hour >= (((SELECT endb FROM p) - $4::interval) AT TIME ZONE $3) AND date_trunc($2, h.hour AT TIME ZONE $3) = b.b
		GROUP BY b.b ORDER BY b.b`, tenantID, p.unit, tz, p.span, p.step, siteArg(site))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := &statsSeries{}
	for rows.Next() {
		var b time.Time
		var a, r int64
		if err := rows.Scan(&b, &a, &r); err != nil {
			return nil, err
		}
		out.Labels = append(out.Labels, b.Format(p.axisFmt))
		out.Tips = append(out.Tips, fmt.Sprintf("%s — accepted %d, rejected %d", b.Format(p.tipFmt), a, r))
		out.Accepts, out.Rejects = append(out.Accepts, a), append(out.Rejects, r)
		out.TotalA += a
		out.TotalR += r
	}
	return out, rows.Err()
}

type reasonRow struct {
	Category string
	N        int64
	Pct      int
}

func (s *server) statsPage(w http.ResponseWriter, r *http.Request, u *User) {
	ctx := r.Context()
	rng := r.URL.Query().Get("range")
	p, ok := periods[rng]
	if !ok {
		rng, p = "day", periods["day"]
	}
	loc, tz := s.statsLoc(r)
	site, sites := s.siteFilter(r, u.Tenant.ID)
	ser, err := s.statsSeries(ctx, u.Tenant.ID, site, tz, p)
	if err != nil {
		s.fail(w, r, u, err)
		return
	}
	// start of the window, for reasons / clients
	var start time.Time
	s.a.St.RO.QueryRow(ctx, `SELECT ((date_trunc($1, now() AT TIME ZONE $2) - $3::interval) AT TIME ZONE $2)`, p.unit, tz, p.span).Scan(&start)

	var reasons []reasonRow
	var rejTotal int64
	rows, _ := s.a.St.RO.Query(ctx, `SELECT category, sum(n)::bigint FROM stats_reasons WHERE tenant_id=$1::uuid AND ($3::uuid IS NULL OR site_id=$3::uuid) AND hour >= $2
		GROUP BY category ORDER BY 2 DESC`, u.Tenant.ID, start, siteArg(site))
	for rows.Next() {
		var x reasonRow
		rows.Scan(&x.Category, &x.N)
		rejTotal += x.N
		reasons = append(reasons, x)
	}
	rows.Close()
	for i := range reasons {
		if rejTotal > 0 {
			reasons[i].Pct = int(reasons[i].N * 100 / rejTotal)
		}
	}
	var activeClients, newClients, privateMACs int
	s.a.St.RO.QueryRow(ctx, `SELECT count(*) FILTER (WHERE last_seen >= $2), count(*) FILTER (WHERE first_seen >= $2) FROM client_stats WHERE tenant_id=$1::uuid`, u.Tenant.ID, start).Scan(&activeClients, &newClients)
	_ = privateMACs

	okRate := "—"
	if t := ser.TotalA + ser.TotalR; t > 0 {
		okRate = fmt.Sprintf("%.1f%%", float64(ser.TotalR)*100/float64(t))
	}
	both := stackedBars("Accepted and rejected authentications", ser.Labels, ser.Tips,
		[]chartSeries{{"Accepted", "c-ok", ser.Accepts}, {"Rejected", "c-bad", ser.Rejects}})
	rejOnly := stackedBars("Rejected authentications", ser.Labels, ser.Tips, []chartSeries{{"Rejected", "c-bad", ser.Rejects}})

	// latest rejects (raw events, within event retention)
	type recent struct{ Time, Client, AP, Subject, Reason string }
	var recents []recent
	rr, _ := s.a.St.RO.Query(ctx, `SELECT ts, COALESCE(client_mac,''), COALESCE(ap,''), data->>'subject', data->>'reason' FROM events
		WHERE tenant_id=$1::uuid AND kind='auth' AND data->>'result'='reject' AND ($2::uuid IS NULL OR site_id=$2::uuid) ORDER BY ts DESC LIMIT 10`, u.Tenant.ID, siteArg(site))
	for rr.Next() {
		var t time.Time
		var x recent
		var subj, reason *string
		rr.Scan(&t, &x.Client, &x.AP, &subj, &reason)
		x.Time = t.In(loc).Format("2006-01-02 15:04")
		if subj != nil {
			x.Subject = *subj
		}
		if reason != nil {
			x.Reason = *reason
		}
		recents = append(recents, x)
	}
	rr.Close()

	s.render(w, r, u, "stats", page{"Title": "Stats", "Tab": "overview", "Range": rng, "RangeLabel": p.label, "Sites": sites, "Site": site, "TZ": tz,
		"Both": both, "RejOnly": rejOnly, "TotalA": ser.TotalA, "TotalR": ser.TotalR, "RejectRate": okRate, "Reasons": reasons,
		"Active": activeClients, "New": newClients, "Recent": recents,
		"Rows": statRows(ser)})
}

type statRow struct {
	Label            string
	Accepts, Rejects int64
}

func statRows(s *statsSeries) []statRow {
	out := make([]statRow, len(s.Labels))
	for i := range out {
		out[i] = statRow{s.Labels[i], s.Accepts[i], s.Rejects[i]}
	}
	return out
}

// ---- clients ----

type clientRow struct {
	MAC, Subject, LastAP, LastSSID string
	Private                        bool
	First, Last                    string
	Accepts, Rejects, Sessions     int64
	Roams                          int64
	APs                            int
}

var clientSorts = map[string]string{"last_seen": "c.last_seen", "first_seen": "c.first_seen", "accepts": "c.accepts", "rejects": "c.rejects", "roams": "c.roams", "sessions": "c.sessions"}

func (s *server) statsClients(w http.ResponseWriter, r *http.Request, u *User) {
	ctx := r.Context()
	loc, _ := s.statsLoc(r)
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	sortKey := r.URL.Query().Get("sort")
	col, ok := clientSorts[sortKey]
	if !ok {
		sortKey, col = "last_seen", "c.last_seen"
	}
	filter := r.URL.Query().Get("f")
	pg, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if pg < 1 {
		pg = 1
	}
	const per = 50
	where := ` WHERE c.tenant_id=$1::uuid AND ($2 = '' OR c.mac ILIKE '%'||$2||'%' OR c.last_subject ILIKE '%'||$2||'%')`
	switch filter {
	case "new24":
		where += ` AND c.first_seen >= now() - interval '24 hours'`
	case "new7":
		where += ` AND c.first_seen >= now() - interval '7 days'`
	case "roamers":
		where += ` AND c.roams > 0`
	case "rejected":
		where += ` AND c.rejects > 0`
	case "private":
		where += ` AND (('x'||substr(c.mac,1,2))::bit(8)::int & 2) = 2`
	default:
		filter = ""
	}
	var total int
	s.a.St.RO.QueryRow(ctx, `SELECT count(*) FROM client_stats c`+where, u.Tenant.ID, q).Scan(&total)
	rows, err := s.a.St.RO.Query(ctx, `SELECT c.mac, c.last_subject, c.last_ap, c.last_ssid, c.first_seen, c.last_seen, c.accepts, c.rejects, c.sessions, c.roams,
		(SELECT count(*) FROM client_aps a WHERE a.tenant_id=c.tenant_id AND a.mac=c.mac) FROM client_stats c`+where+` ORDER BY `+col+` DESC, c.mac LIMIT $3 OFFSET $4`, u.Tenant.ID, q, per, (pg-1)*per)
	if err != nil {
		s.fail(w, r, u, err)
		return
	}
	var list []clientRow
	for rows.Next() {
		var c clientRow
		var f, l time.Time
		rows.Scan(&c.MAC, &c.Subject, &c.LastAP, &c.LastSSID, &f, &l, &c.Accepts, &c.Rejects, &c.Sessions, &c.Roams, &c.APs)
		c.First, c.Last, c.Private = tfmt(&f, loc), tfmt(&l, loc), isPrivateMAC(c.MAC)
		list = append(list, c)
	}
	rows.Close()
	s.render(w, r, u, "stats_clients", page{"Title": "Stats", "Tab": "clients", "Clients": list, "Q": q, "Sort": sortKey, "Filter": filter, "Total": total, "Page": pg, "Pages": (total + per - 1) / per})
}

type actRow struct {
	Time, Kind, Detail, AP, SSID, Reason, VLAN string
	Roam                                       bool
}

func (s *server) statsClient(w http.ResponseWriter, r *http.Request, u *User) {
	ctx := r.Context()
	loc, _ := s.statsLoc(r)
	mac := normMAC(r.PathValue("mac"))
	if mac == "" {
		s.render(w, r, u, "error", page{"Title": "Not found", "Msg": "Not found."}, 404)
		return
	}
	var c clientRow
	var f, l time.Time
	err := s.a.St.RO.QueryRow(ctx, `SELECT mac, last_subject, last_ap, last_ssid, first_seen, last_seen, accepts, rejects, sessions, roams FROM client_stats WHERE tenant_id=$1::uuid AND mac=$2`,
		u.Tenant.ID, mac).Scan(&c.MAC, &c.Subject, &c.LastAP, &c.LastSSID, &f, &l, &c.Accepts, &c.Rejects, &c.Sessions, &c.Roams)
	if err != nil {
		s.render(w, r, u, "error", page{"Title": "Not found", "Msg": "That client has not been seen by this tenant."}, 404)
		return
	}
	c.First, c.Last, c.Private = tfmt(&f, loc), tfmt(&l, loc), isPrivateMAC(mac)

	type apHist struct {
		AP, First, Last            string
		Accepts, Rejects, Sessions int64
	}
	var aps []apHist
	rows, _ := s.a.St.RO.Query(ctx, `SELECT ap, first_seen, last_seen, accepts, rejects, sessions FROM client_aps WHERE tenant_id=$1::uuid AND mac=$2 ORDER BY last_seen DESC`, u.Tenant.ID, mac)
	for rows.Next() {
		var x apHist
		var a, b time.Time
		rows.Scan(&x.AP, &a, &b, &x.Accepts, &x.Rejects, &x.Sessions)
		x.First, x.Last = tfmt(&a, loc), tfmt(&b, loc)
		aps = append(aps, x)
	}
	rows.Close()

	// recent activity from the raw events (within event retention), oldest first to detect roams
	var acts []actRow
	var up, down int64
	er, _ := s.a.St.RO.Query(ctx, `SELECT ts, kind, data FROM events WHERE tenant_id=$1::uuid AND client_mac=$2 ORDER BY ts DESC LIMIT 200`, u.Tenant.ID, mac)
	type ev struct {
		t    time.Time
		kind string
		d    map[string]string
	}
	var evs []ev
	for er.Next() {
		var e ev
		er.Scan(&e.t, &e.kind, &e.d)
		evs = append(evs, e)
	}
	er.Close()
	lastAP, lastAt := "", time.Time{}
	for i := len(evs) - 1; i >= 0; i-- {
		e := evs[i]
		a := actRow{Time: e.t.In(loc).Format("2006-01-02 15:04:05"), Kind: e.kind, AP: e.d["ap"], SSID: ssidOf(e.d["ssid"]), VLAN: e.d["vlan"]}
		connect := false
		switch e.kind {
		case "auth":
			a.Detail, a.Reason = e.d["result"], e.d["reason"]
			connect = e.d["result"] == "accept"
		case "acct":
			a.Detail = "accounting " + strings.ToLower(e.d["status"])
			connect = e.d["status"] == "Start"
		}
		if connect && a.AP != "" {
			if lastAP != "" && a.AP != lastAP && e.t.Sub(lastAt) < roamWindow {
				a.Roam = true
			}
			lastAP, lastAt = a.AP, e.t
		}
		acts = append([]actRow{a}, acts...)
	}
	s.a.St.RO.QueryRow(ctx, `WITH s AS (SELECT data->>'session_id' sid,
		max((data->>'in_octets')::bigint + COALESCE((data->>'in_gigawords')::bigint,0)*4294967296) i,
		max((data->>'out_octets')::bigint + COALESCE((data->>'out_gigawords')::bigint,0)*4294967296) o
		FROM events WHERE tenant_id=$1::uuid AND client_mac=$2 AND kind='acct' AND ts > now() - interval '30 days' GROUP BY 1)
		SELECT COALESCE(sum(i),0)::bigint, COALESCE(sum(o),0)::bigint FROM s`, u.Tenant.ID, mac).Scan(&up, &down)

	s.render(w, r, u, "stats_client", page{"Title": "Client " + mac, "Tab": "clients", "C": c, "APs": aps, "Acts": acts, "Up": fmtBytes(up), "Down": fmtBytes(down)})
}

// ---- reports ----

func (s *server) statsReports(w http.ResponseWriter, r *http.Request, u *User) {
	_, sites := s.siteFilter(r, u.Tenant.ID)
	g := s.a.General(r.Context())
	s.render(w, r, u, "stats_reports", page{"Title": "Stats", "Tab": "reports", "Sites": sites, "RetentionDays": g.EventRetentionDays, "TZ": g.Timezone, "Today": time.Now().Format("2006-01-02")})
}

type reportSpec struct {
	Title   string
	Columns []string
}

var reportDefs = map[string]reportSpec{
	"ap-usage":    {"Access point usage", []string{"Site", "Access point", "Accepted authentications", "Rejected authentications", "Unique clients", "Sessions", "Upload bytes (from clients)", "Download bytes (to clients)", "Total bytes", "Session time (s)", "Last activity"}},
	"top-talkers": {"Top talkers", []string{"Rank", "Client MAC", "Certificate subject", "Sessions", "Upload bytes (from client)", "Download bytes (to client)", "Total bytes", "Session time (s)", "Access points used", "Last seen"}},
	"rejects":     {"Rejected authentications", []string{"Time", "Client MAC", "Certificate subject", "Access point", "SSID", "Reason category", "Reason"}},
	"clients":     {"Clients", []string{"Client MAC", "Private MAC", "Certificate subject", "First seen", "Last seen", "Connects", "Rejects", "Sessions", "Roams", "Last access point", "Last SSID"}},
}

type reportTable struct {
	Title, Range, TZ, Note string
	Columns                []string
	Rows                   [][]string
	Truncated              bool
}

// reportRange parses preset/from/to in the viewing time zone. Event-based reports are clamped to the event retention.
func (s *server) reportRange(r *http.Request, loc *time.Location) (start, end time.Time, label string, clamped bool) {
	now := time.Now().In(loc)
	end = now
	switch r.URL.Query().Get("preset") {
	case "24h":
		start = now.Add(-24 * time.Hour)
	case "30d":
		start = now.AddDate(0, 0, -30)
	case "90d":
		start = now.AddDate(0, 0, -90)
	case "custom":
		f, e1 := time.ParseInLocation("2006-01-02", r.URL.Query().Get("from"), loc)
		t, e2 := time.ParseInLocation("2006-01-02", r.URL.Query().Get("to"), loc)
		if e1 == nil && e2 == nil && !t.Before(f) {
			start, end = f, t.AddDate(0, 0, 1)
		} else {
			start = now.AddDate(0, 0, -7)
		}
	default:
		start = now.AddDate(0, 0, -7)
	}
	if end.After(now) {
		end = now
	}
	label = start.In(loc).Format("2006-01-02 15:04") + " – " + end.In(loc).Format("2006-01-02 15:04")
	return
}

func csvSafe(s string) string {
	if s != "" && strings.ContainsAny(s[:1], "=+-@\t\r") {
		return "'" + s
	}
	return s
}

func (s *server) statsReport(w http.ResponseWriter, r *http.Request, u *User) {
	ctx := r.Context()
	kind := r.PathValue("type")
	def, ok := reportDefs[kind]
	if !ok {
		s.render(w, r, u, "error", page{"Title": "Not found", "Msg": "Unknown report."}, 404)
		return
	}
	loc, tz := s.statsLoc(r)
	site, _ := s.siteFilter(r, u.Tenant.ID)
	start, end, label, _ := s.reportRange(r, loc)
	g := s.a.General(ctx)
	note := ""
	if kind != "clients" {
		if min := time.Now().AddDate(0, 0, -g.EventRetentionDays); start.Before(min) {
			start = min
			note = fmt.Sprintf("Detailed events are kept for %d days, so this report starts at %s.", g.EventRetentionDays, min.In(loc).Format("2006-01-02"))
			label = start.In(loc).Format("2006-01-02 15:04") + " – " + end.In(loc).Format("2006-01-02 15:04")
		}
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit < 1 || limit > 100000 {
		limit = map[string]int{"top-talkers": 25}[kind]
		if limit == 0 {
			limit = 1000
		}
	}
	format := r.URL.Query().Get("format")
	htmlLimit := 500
	if format != "csv" && limit > htmlLimit {
		limit = htmlLimit
	}
	tbl := &reportTable{Title: def.Title, Range: label, TZ: tz, Note: note, Columns: append([]string(nil), def.Columns...)} // copy: the HTML view renames columns
	var err error
	switch kind {
	case "ap-usage":
		err = s.reportAPUsage(ctx, u.Tenant.ID, site, start, end, loc, tbl)
	case "top-talkers":
		err = s.reportTopTalkers(ctx, u.Tenant.ID, site, start, end, loc, limit, tbl)
	case "rejects":
		err = s.reportRejects(ctx, u.Tenant.ID, site, start, end, loc, limit, tbl)
	case "clients":
		err = s.reportClients(ctx, u.Tenant.ID, start, end, loc, limit, tbl)
	}
	if err != nil {
		s.fail(w, r, u, err)
		return
	}
	s.a.Audit(ctx, u.Email, "stats.report", kind+" "+format)
	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="radman-%s-%s-%s-%s.csv"`, u.Tenant.Slug, kind, start.In(loc).Format("20060102"), end.In(loc).Format("20060102")))
		w.Header().Set("Cache-Control", "no-store")
		w.Write([]byte("\xef\xbb\xbf")) // UTF-8 BOM so Excel reads accents correctly
		cw := csv.NewWriter(w)
		cw.Write(tbl.Columns)
		for _, row := range tbl.Rows {
			out := make([]string, len(row))
			for i, c := range row {
				out[i] = csvSafe(c)
			}
			cw.Write(out)
		}
		cw.Flush()
		return
	}
	// printable view: bytes and durations are shown in human units (the CSV keeps the raw numbers for spreadsheets)
	for ci, col := range tbl.Columns {
		switch {
		case strings.Contains(col, "bytes"):
			for _, row := range tbl.Rows {
				n, _ := strconv.ParseInt(row[ci], 10, 64)
				row[ci] = fmtBytes(n)
			}
			tbl.Columns[ci] = strings.TrimSuffix(strings.ReplaceAll(col, " bytes", ""), " ")
		case strings.HasSuffix(col, "(s)"):
			for _, row := range tbl.Rows {
				n, _ := strconv.ParseInt(row[ci], 10, 64)
				row[ci] = fmtDur(n)
			}
			tbl.Columns[ci] = strings.TrimSuffix(col, " (s)")
		}
	}
	s.render(w, r, u, "stats_report", page{"Title": def.Title, "R": tbl, "Generated": time.Now().In(loc).Format("2006-01-02 15:04"), "Kind": kind, "Query": r.URL.RawQuery})
}

func (s *server) reportAPUsage(ctx context.Context, tenant, site string, start, end time.Time, loc *time.Location, t *reportTable) error {
	rows, err := s.a.St.RO.Query(ctx, `
		WITH a AS (
		  SELECT site_id, ap, count(*) FILTER (WHERE kind='auth' AND data->>'result'='accept') acc, count(*) FILTER (WHERE kind='auth' AND data->>'result'='reject') rej,
		         count(DISTINCT client_mac) clients, max(ts) last_ts
		  FROM events WHERE tenant_id=$1::uuid AND ts >= $2 AND ts < $3 AND ap IS NOT NULL AND ap <> '' AND ($4::uuid IS NULL OR site_id=$4::uuid) GROUP BY site_id, ap),
		sess AS (
		  SELECT site_id, ap, data->>'session_id' sid,
		    max((data->>'in_octets')::bigint + COALESCE((data->>'in_gigawords')::bigint,0)*4294967296) i,
		    max((data->>'out_octets')::bigint + COALESCE((data->>'out_gigawords')::bigint,0)*4294967296) o,
		    max((data->>'session_time')::bigint) dur
		  FROM events WHERE tenant_id=$1::uuid AND kind='acct' AND ts >= $2 AND ts < $3 AND ap IS NOT NULL AND ap <> '' AND ($4::uuid IS NULL OR site_id=$4::uuid) GROUP BY 1,2,3),
		u AS (SELECT site_id, ap, count(*) sessions, sum(i) i, sum(o) o, sum(dur) dur FROM sess GROUP BY 1,2)
		SELECT COALESCE(s.name,''), a.ap, a.acc, a.rej, a.clients, COALESCE(u.sessions,0), COALESCE(u.i,0)::bigint, COALESCE(u.o,0)::bigint, COALESCE(u.dur,0)::bigint, a.last_ts
		FROM a LEFT JOIN u ON u.site_id=a.site_id AND u.ap=a.ap LEFT JOIN sites s ON s.id=a.site_id ORDER BY COALESCE(u.i,0)+COALESCE(u.o,0) DESC, a.ap`, tenant, start, end, siteArg(site))
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var site, ap string
		var acc, rej, clients, sessions, up, down, dur int64
		var last time.Time
		if err := rows.Scan(&site, &ap, &acc, &rej, &clients, &sessions, &up, &down, &dur, &last); err != nil {
			return err
		}
		t.Rows = append(t.Rows, []string{site, ap, i64(acc), i64(rej), i64(clients), i64(sessions), i64(up), i64(down), i64(up + down), i64(dur), last.In(loc).Format("2006-01-02 15:04:05")})
	}
	return rows.Err()
}

func (s *server) reportTopTalkers(ctx context.Context, tenant, site string, start, end time.Time, loc *time.Location, limit int, t *reportTable) error {
	rows, err := s.a.St.RO.Query(ctx, `
		WITH sess AS (
		  SELECT client_mac, ap, data->>'session_id' sid,
		    max((data->>'in_octets')::bigint + COALESCE((data->>'in_gigawords')::bigint,0)*4294967296) i,
		    max((data->>'out_octets')::bigint + COALESCE((data->>'out_gigawords')::bigint,0)*4294967296) o,
		    max((data->>'session_time')::bigint) dur, max(ts) last_ts
		  FROM events WHERE tenant_id=$1::uuid AND kind='acct' AND client_mac IS NOT NULL AND ts >= $2 AND ts < $3 AND ($4::uuid IS NULL OR site_id=$4::uuid) GROUP BY 1,2,3)
		SELECT s.client_mac, COALESCE(c.last_subject,''), count(*), sum(s.i)::bigint, sum(s.o)::bigint, sum(s.dur)::bigint, count(DISTINCT s.ap), max(s.last_ts)
		FROM sess s LEFT JOIN client_stats c ON c.tenant_id=$1::uuid AND c.mac=s.client_mac
		GROUP BY s.client_mac, c.last_subject ORDER BY sum(s.i)+sum(s.o) DESC, s.client_mac LIMIT $5`, tenant, start, end, siteArg(site), limit)
	if err != nil {
		return err
	}
	defer rows.Close()
	rank := 0
	for rows.Next() {
		var mac, subj string
		var sessions, up, down, dur, aps int64
		var last time.Time
		if err := rows.Scan(&mac, &subj, &sessions, &up, &down, &dur, &aps, &last); err != nil {
			return err
		}
		rank++
		t.Rows = append(t.Rows, []string{i64(int64(rank)), mac, subj, i64(sessions), i64(up), i64(down), i64(up + down), i64(dur), i64(aps), last.In(loc).Format("2006-01-02 15:04:05")})
	}
	return rows.Err()
}

func (s *server) reportRejects(ctx context.Context, tenant, site string, start, end time.Time, loc *time.Location, limit int, t *reportTable) error {
	rows, err := s.a.St.RO.Query(ctx, `SELECT ts, COALESCE(client_mac,''), COALESCE(data->>'subject',''), COALESCE(ap,''), COALESCE(data->>'ssid',''), COALESCE(data->>'reason','')
		FROM events WHERE tenant_id=$1::uuid AND kind='auth' AND data->>'result'='reject' AND ts >= $2 AND ts < $3 AND ($4::uuid IS NULL OR site_id=$4::uuid)
		ORDER BY ts DESC LIMIT $5`, tenant, start, end, siteArg(site), limit)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var ts time.Time
		var mac, subj, ap, ssid, reason string
		if err := rows.Scan(&ts, &mac, &subj, &ap, &ssid, &reason); err != nil {
			return err
		}
		t.Rows = append(t.Rows, []string{ts.In(loc).Format("2006-01-02 15:04:05"), mac, subj, ap, ssidOf(ssid), ReasonCategory(reason), reason})
	}
	return rows.Err()
}

func (s *server) reportClients(ctx context.Context, tenant string, start, end time.Time, loc *time.Location, limit int, t *reportTable) error {
	rows, err := s.a.St.RO.Query(ctx, `SELECT mac, last_subject, first_seen, last_seen, accepts, rejects, sessions, roams, last_ap, last_ssid FROM client_stats
		WHERE tenant_id=$1::uuid AND last_seen >= $2 AND first_seen < $3 ORDER BY last_seen DESC LIMIT $4`, tenant, start, end, limit)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var mac, subj, ap, ssid string
		var f, l time.Time
		var acc, rej, ses, roams int64
		if err := rows.Scan(&mac, &subj, &f, &l, &acc, &rej, &ses, &roams, &ap, &ssid); err != nil {
			return err
		}
		t.Rows = append(t.Rows, []string{mac, map[bool]string{true: "yes", false: "no"}[isPrivateMAC(mac)], subj, f.In(loc).Format("2006-01-02 15:04:05"), l.In(loc).Format("2006-01-02 15:04:05"), i64(acc), i64(rej), i64(ses), i64(roams), ap, ssid})
	}
	return rows.Err()
}

func i64(n int64) string { return strconv.FormatInt(n, 10) }

var _ template.HTML
