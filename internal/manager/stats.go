package manager

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"radman/internal/proto"
)

// Statistics are maintained as rollups at ingest time, so graphs and client history keep working for months or years
// even though the raw auth/accounting events are purged after the (shorter) event retention period.
//
//	stats_hourly / stats_reasons   accepted & rejected authentications per site per hour, rejects by category
//	client_stats / client_aps      first/last seen, connects, rejects, sessions, roams, and the APs each client used

// roamWindow: a connection on a different AP than the previous one, within this time, counts as a roam.
const roamWindow = time.Hour

// statEvent is one event with the tenant/site it belongs to.
type statEvent struct {
	Tenant, Site string
	proto.Event
}

// normMAC lower-cases a MAC and uses ':' separators ("F6-08-AB-9A-8D-E6" -> "f6:08:ab:9a:8d:e6"). Anything else yields "".
func normMAC(s string) string {
	s = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(s, "-", ":")))
	if len(s) != 17 {
		return ""
	}
	for i := 0; i < 17; i++ {
		c := s[i]
		if i%3 == 2 {
			if c != ':' {
				return ""
			}
		} else if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return ""
		}
	}
	return s
}

// isPrivateMAC reports a locally administered address (what phones use when "private Wi-Fi address" is on).
func isPrivateMAC(mac string) bool {
	if len(mac) < 2 {
		return false
	}
	var b byte
	fmt.Sscanf(mac[:2], "%x", &b)
	return b&0x02 != 0
}

// ssidOf extracts the SSID from a Called-Station-Id such as "76-22-32-2C-50-EF:Oak Lodge EAP".
func ssidOf(called string) string {
	if _, ssid, ok := strings.Cut(called, ":"); ok {
		return ssid
	}
	return ""
}

// ReasonCategory buckets a free-text reject reason so that long-term statistics have a small, stable set of labels.
func ReasonCategory(reason string) string {
	r := strings.ToLower(reason)
	switch {
	case reason == "":
		return "other"
	case strings.Contains(r, "revoked"):
		return "Revoked certificate"
	case strings.Contains(r, "expired or is not yet valid") || strings.Contains(r, "has expired"):
		return "Expired certificate"
	case strings.Contains(r, "stale") || strings.Contains(r, "no crl"):
		return "Revocation list unavailable"
	case strings.Contains(r, "denied by rule") || strings.Contains(r, "default deny") || strings.Contains(r, "no rule matched"):
		return "Denied by policy"
	case strings.Contains(r, "unknown authority") || strings.Contains(r, "no pki profile") || strings.Contains(r, "not authorized to sign"):
		return "Untrusted certificate authority"
	case strings.Contains(r, "remote error"):
		return "Client aborted TLS (often distrusts the server certificate)"
	case strings.Contains(r, "didn't provide a certificate") || strings.Contains(r, "no client certificate"):
		return "No client certificate"
	case strings.Contains(r, "extended master secret"):
		return "Supplicant unsupported (no extended master secret)"
	case strings.Contains(r, "timeout"):
		return "Handshake timeout"
	}
	return "Other"
}

type clientAgg struct {
	first, last                       time.Time
	accepts, rejects, sessions, roams int64
	lastAP, lastSSID, lastSubject     string
	lastAPAt                          *time.Time
	dirty                             bool
}

type apAgg struct {
	first, last                time.Time
	accepts, rejects, sessions int64
}

// recordStats folds events into the rollups inside the caller's transaction (so a stored event is always counted exactly once).
// Events must be the ones newly inserted (duplicates are filtered by the caller).
func (a *App) recordStats(ctx context.Context, tx pgx.Tx, evs []statEvent) error {
	if len(evs) == 0 {
		return nil
	}
	sort.SliceStable(evs, func(i, j int) bool { return evs[i].Time.Before(evs[j].Time) })

	type hk struct {
		tenant, site string
		hour         time.Time
	}
	type rk struct {
		hk
		cat string
	}
	hours := map[hk][2]int64{}
	reasons := map[rk]int64{}
	byTenant := map[string][]statEvent{}
	for _, e := range evs {
		byTenant[e.Tenant] = append(byTenant[e.Tenant], e)
		if e.Kind != "auth" {
			continue
		}
		k := hk{e.Tenant, e.Site, e.Time.UTC().Truncate(time.Hour)}
		c := hours[k]
		switch e.Data["result"] {
		case "accept":
			c[0]++
		case "reject":
			c[1]++
			reasons[rk{k, ReasonCategory(e.Data["reason"])}]++
		}
		hours[k] = c
	}

	b := &pgx.Batch{}
	for k, c := range hours {
		b.Queue(`INSERT INTO stats_hourly(tenant_id,site_id,hour,accepts,rejects) VALUES($1::uuid,$2::uuid,$3,$4,$5)
			ON CONFLICT (tenant_id,site_id,hour) DO UPDATE SET accepts=stats_hourly.accepts+EXCLUDED.accepts, rejects=stats_hourly.rejects+EXCLUDED.rejects`,
			k.tenant, k.site, k.hour, c[0], c[1])
	}
	for k, n := range reasons {
		b.Queue(`INSERT INTO stats_reasons(tenant_id,site_id,hour,category,n) VALUES($1::uuid,$2::uuid,$3,$4,$5)
			ON CONFLICT (tenant_id,site_id,hour,category) DO UPDATE SET n=stats_reasons.n+EXCLUDED.n`, k.tenant, k.site, k.hour, k.cat, n)
	}
	if err := execBatch(ctx, tx, b); err != nil {
		return err
	}
	for tenant, list := range byTenant {
		if err := a.recordClients(ctx, tx, tenant, list); err != nil {
			return err
		}
	}
	return nil
}

func execBatch(ctx context.Context, tx pgx.Tx, b *pgx.Batch) error {
	if b.Len() == 0 {
		return nil
	}
	br := tx.SendBatch(ctx, b)
	for i := 0; i < b.Len(); i++ {
		if _, err := br.Exec(); err != nil {
			br.Close()
			return err
		}
	}
	return br.Close()
}

func (a *App) recordClients(ctx context.Context, tx pgx.Tx, tenant string, evs []statEvent) error {
	macSet := map[string]time.Time{}
	for _, e := range evs {
		if m := normMAC(e.Data["client_mac"]); m != "" {
			if t, ok := macSet[m]; !ok || e.Time.Before(t) {
				macSet[m] = e.Time
			}
		}
	}
	if len(macSet) == 0 {
		return nil
	}
	macs := make([]string, 0, len(macSet))
	for m := range macSet {
		macs = append(macs, m)
	}
	sort.Strings(macs) // consistent lock order between concurrent check-ins

	b := &pgx.Batch{}
	for _, m := range macs {
		b.Queue(`INSERT INTO client_stats(tenant_id,mac,first_seen,last_seen) VALUES($1::uuid,$2,$3,$3) ON CONFLICT DO NOTHING`, tenant, m, macSet[m])
	}
	if err := execBatch(ctx, tx, b); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT mac, first_seen, last_seen, accepts, rejects, sessions, roams, last_ap, last_ap_at, last_ssid, last_subject
		FROM client_stats WHERE tenant_id=$1::uuid AND mac = ANY($2) ORDER BY mac FOR UPDATE`, tenant, macs)
	if err != nil {
		return err
	}
	agg := map[string]*clientAgg{}
	for rows.Next() {
		var mac string
		c := &clientAgg{}
		if err := rows.Scan(&mac, &c.first, &c.last, &c.accepts, &c.rejects, &c.sessions, &c.roams, &c.lastAP, &c.lastAPAt, &c.lastSSID, &c.lastSubject); err != nil {
			rows.Close()
			return err
		}
		agg[mac] = c
	}
	rows.Close()
	aps := map[[2]string]*apAgg{}

	for _, e := range evs {
		mac := normMAC(e.Data["client_mac"])
		c := agg[mac]
		if c == nil {
			continue
		}
		c.dirty = true
		if e.Time.Before(c.first) {
			c.first = e.Time
		}
		if e.Time.After(c.last) {
			c.last = e.Time
		}
		ap := e.Data["ap"]
		var apa *apAgg
		if ap != "" {
			k := [2]string{mac, ap}
			if apa = aps[k]; apa == nil {
				apa = &apAgg{first: e.Time, last: e.Time}
				aps[k] = apa
			}
			if e.Time.Before(apa.first) {
				apa.first = e.Time
			}
			if e.Time.After(apa.last) {
				apa.last = e.Time
			}
		}
		connect := false
		switch e.Kind {
		case "auth":
			switch e.Data["result"] {
			case "accept":
				c.accepts++
				connect = true
				if s := e.Data["subject"]; s != "" {
					c.lastSubject = s
				}
				if apa != nil {
					apa.accepts++
				}
			case "reject":
				c.rejects++
				if apa != nil {
					apa.rejects++
				}
			}
		case "acct":
			if e.Data["status"] == "Start" {
				c.sessions++
				connect = true
				if apa != nil {
					apa.sessions++
				}
			}
		}
		if connect && ap != "" {
			if c.lastAP != "" && ap != c.lastAP && c.lastAPAt != nil && !e.Time.Before(*c.lastAPAt) && e.Time.Sub(*c.lastAPAt) < roamWindow {
				c.roams++
			}
			if c.lastAPAt == nil || !e.Time.Before(*c.lastAPAt) {
				t := e.Time
				c.lastAP, c.lastAPAt = ap, &t
				if s := ssidOf(e.Data["ssid"]); s != "" {
					c.lastSSID = s
				}
			}
		}
	}

	b = &pgx.Batch{}
	for mac, c := range agg {
		if c.dirty {
			b.Queue(`UPDATE client_stats SET first_seen=$3,last_seen=$4,accepts=$5,rejects=$6,sessions=$7,roams=$8,last_ap=$9,last_ap_at=$10,last_ssid=$11,last_subject=$12
				WHERE tenant_id=$1::uuid AND mac=$2`, tenant, mac, c.first, c.last, c.accepts, c.rejects, c.sessions, c.roams, c.lastAP, c.lastAPAt, c.lastSSID, c.lastSubject)
		}
	}
	for k, x := range aps {
		b.Queue(`INSERT INTO client_aps(tenant_id,mac,ap,first_seen,last_seen,accepts,rejects,sessions) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8)
			ON CONFLICT (tenant_id,mac,ap) DO UPDATE SET first_seen=LEAST(client_aps.first_seen,EXCLUDED.first_seen), last_seen=GREATEST(client_aps.last_seen,EXCLUDED.last_seen),
			accepts=client_aps.accepts+EXCLUDED.accepts, rejects=client_aps.rejects+EXCLUDED.rejects, sessions=client_aps.sessions+EXCLUDED.sessions`,
			tenant, k[0], k[1], x.first, x.last, x.accepts, x.rejects, x.sessions)
	}
	return execBatch(ctx, tx, b)
}

// storeEvents inserts a node's events and folds the newly inserted ones into the statistics, in one transaction.
// It returns the highest sequence number received (the ack).
func (a *App) storeEvents(ctx context.Context, id *nodeIdentity, events []proto.Event) (uint64, error) {
	tx, err := a.St.DB.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	b := &pgx.Batch{}
	var acked uint64
	for _, e := range events {
		b.Queue(`INSERT INTO events(node_id,site_id,tenant_id,seq,ts,kind,data) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (node_id, seq, ts) DO NOTHING`,
			id.ID, id.SiteID, id.TenantID, e.Seq, e.Time, e.Kind, jsonOf(e.Data))
		if e.Seq > acked {
			acked = e.Seq
		}
	}
	br := tx.SendBatch(ctx, b)
	var fresh []statEvent
	for _, e := range events {
		tag, err := br.Exec()
		if err != nil {
			br.Close()
			return 0, err
		}
		if tag.RowsAffected() == 1 { // a retried batch must not be counted twice
			fresh = append(fresh, statEvent{Tenant: id.TenantID, Site: id.SiteID, Event: e})
		}
	}
	if err := br.Close(); err != nil {
		return 0, err
	}
	if err := a.recordStats(ctx, tx, fresh); err != nil {
		return 0, fmt.Errorf("statistics: %w", err)
	}
	return acked, tx.Commit(ctx)
}

// backfillStats builds the rollups from events stored before statistics existed, once, replaying them through the live code path.
func (a *App) backfillStats(ctx context.Context) error {
	var done bool
	a.St.GetJSON(ctx, "stats_backfilled", &done)
	if done {
		return nil
	}
	var err error
	a.runExclusive(ctx, lockStatsBackfill, func(ctx context.Context) {
		a.St.GetJSON(ctx, "stats_backfilled", &done)
		if done {
			return
		}
		var ts time.Time
		var lastID int64
		total := 0
		for {
			rows, qerr := a.St.DB.Query(ctx, `SELECT id, tenant_id::text, site_id::text, node_id::text, seq, ts, kind, data FROM events
				WHERE tenant_id IS NOT NULL AND (ts, id) > ($1, $2) ORDER BY ts, id LIMIT 5000`, ts, lastID)
			if qerr != nil {
				err = qerr
				return
			}
			var chunk []statEvent
			for rows.Next() {
				var e statEvent
				var node string
				var id int64
				if serr := rows.Scan(&id, &e.Tenant, &e.Site, &node, &e.Seq, &e.Time, &e.Kind, &e.Data); serr != nil {
					rows.Close()
					err = serr
					return
				}
				chunk = append(chunk, e)
				ts, lastID = e.Time, id
			}
			rows.Close()
			if len(chunk) == 0 {
				break
			}
			tx, berr := a.St.DB.Begin(ctx)
			if berr != nil {
				err = berr
				return
			}
			if rerr := a.recordStats(ctx, tx, chunk); rerr != nil {
				tx.Rollback(ctx)
				err = rerr
				return
			}
			if cerr := tx.Commit(ctx); cerr != nil {
				err = cerr
				return
			}
			total += len(chunk)
		}
		a.St.SetJSON(ctx, "stats_backfilled", true)
		if total > 0 {
			a.Log.Printf("statistics: backfilled from %d stored events", total)
		}
	})
	return err
}

// purgeStats applies the (longer) statistics retention.
func (a *App) purgeStats(ctx context.Context, days int) {
	cutoff := time.Now().AddDate(0, 0, -days)
	for _, q := range []string{
		`DELETE FROM stats_hourly WHERE hour < $1`, `DELETE FROM stats_reasons WHERE hour < $1`,
		`DELETE FROM client_aps WHERE last_seen < $1`, `DELETE FROM client_stats WHERE last_seen < $1`,
	} {
		a.St.DB.Exec(ctx, q, cutoff)
	}
}

const lockStatsBackfill int64 = 1003
