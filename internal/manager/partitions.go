package manager

import (
	"context"
	"fmt"
	"time"
)

// The events table (auth results + accounting) is the one that grows without bound, so it is range-partitioned by
// month. Retention then means dropping a whole partition (instant, no bloat) instead of a huge DELETE, and old
// partitions can be detached/archived independently.

const partTable = "events"

func monthStart(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
}

func partName(m time.Time) string {
	return fmt.Sprintf("%s_y%04dm%02d", partTable, m.Year(), int(m.Month()))
}

// migrateEvents converts the legacy unpartitioned table (or the freshly created one) into a partitioned table.
func (a *App) migrateEvents(ctx context.Context) error {
	var partitioned bool
	a.St.DB.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_partitioned_table pt JOIN pg_class c ON c.oid=pt.partrelid
		WHERE c.relname='events' AND c.relnamespace=current_schema()::regnamespace)`).Scan(&partitioned)
	if partitioned {
		if err := a.ensureEventColumns(ctx); err != nil {
			return err
		}
		return a.ensurePartitions(ctx)
	}
	tx, err := a.St.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// serialise concurrent first-starts of several manager instances
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(1000)`); err != nil {
		return err
	}
	var again bool
	tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_partitioned_table pt JOIN pg_class c ON c.oid=pt.partrelid WHERE c.relname='events' AND c.relnamespace=current_schema()::regnamespace)`).Scan(&again)
	if again {
		return nil
	}
	steps := []string{
		`ALTER SEQUENCE events_id_seq OWNED BY NONE`,
		`ALTER TABLE events RENAME TO events_legacy`,
		`ALTER TABLE events_legacy RENAME CONSTRAINT events_pkey TO events_legacy_pkey`,
		`ALTER TABLE events_legacy RENAME CONSTRAINT events_node_id_seq_key TO events_legacy_node_id_seq_key`,
		`DROP INDEX IF EXISTS events_kind_ts`,
		`DROP INDEX IF EXISTS events_site_ts`,
		`CREATE TABLE events (
			id bigint NOT NULL DEFAULT nextval('events_id_seq'),
			node_id uuid NOT NULL,
			site_id uuid NOT NULL,
			tenant_id uuid,
			seq bigint NOT NULL,
			ts timestamptz NOT NULL,
			kind text NOT NULL,
			data jsonb NOT NULL,
			client_mac text GENERATED ALWAYS AS (lower(replace(NULLIF(data->>'client_mac',''), '-', ':'))) STORED,
			ap text GENERATED ALWAYS AS (data->>'ap') STORED,
			PRIMARY KEY (id, ts),
			UNIQUE (node_id, seq, ts)
		) PARTITION BY RANGE (ts)`,
		`CREATE TABLE events_default PARTITION OF events DEFAULT`,
	}
	for _, s := range steps {
		if _, err := tx.Exec(ctx, s); err != nil {
			return fmt.Errorf("events migration: %s: %w", s, err)
		}
	}
	var min, max *time.Time
	tx.QueryRow(ctx, `SELECT min(ts), max(ts) FROM events_legacy`).Scan(&min, &max)
	from := monthStart(time.Now())
	if min != nil && min.Before(from) {
		from = monthStart(*min)
	}
	to := monthStart(time.Now()).AddDate(0, 3, 0)
	if max != nil && monthStart(*max).AddDate(0, 1, 0).After(to) {
		to = monthStart(*max).AddDate(0, 1, 0)
	}
	for m := from; m.Before(to); m = m.AddDate(0, 1, 0) {
		if _, err := tx.Exec(ctx, fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s PARTITION OF events FOR VALUES FROM ('%s') TO ('%s')`,
			partName(m), m.Format("2006-01-02"), m.AddDate(0, 1, 0).Format("2006-01-02"))); err != nil {
			return err
		}
	}
	for _, s := range []string{
		`INSERT INTO events(id,node_id,site_id,tenant_id,seq,ts,kind,data) SELECT id,node_id,site_id,tenant_id,seq,ts,kind,data FROM events_legacy`,
		`DROP TABLE events_legacy`,
		`CREATE INDEX events_tenant_kind_ts ON events(tenant_id, kind, ts DESC)`,
		`CREATE INDEX events_site_ts ON events(site_id, ts DESC)`,
		`CREATE INDEX events_tenant_mac_ts ON events(tenant_id, client_mac, ts DESC) WHERE client_mac IS NOT NULL`,
	} {
		if _, err := tx.Exec(ctx, s); err != nil {
			return fmt.Errorf("events migration: %s: %w", s, err)
		}
	}
	return tx.Commit(ctx)
}

// ensurePartitions makes sure the current and the next two months exist (so inserts never fall into the default partition).
func (a *App) ensurePartitions(ctx context.Context) error {
	now := monthStart(time.Now())
	for i := 0; i < 3; i++ {
		m := now.AddDate(0, i, 0)
		if _, err := a.St.DB.Exec(ctx, fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s PARTITION OF events FOR VALUES FROM ('%s') TO ('%s')`,
			partName(m), m.Format("2006-01-02"), m.AddDate(0, 1, 0).Format("2006-01-02"))); err != nil {
			return fmt.Errorf("partition %s: %w", partName(m), err)
		}
	}
	return nil
}

// dropOldPartitions enforces retention: whole months older than the cutoff are dropped, the boundary month is trimmed.
func (a *App) dropOldPartitions(ctx context.Context, retentionDays int) (dropped []string, err error) {
	cutoff := time.Now().AddDate(0, 0, -retentionDays)
	rows, err := a.St.DB.Query(ctx, `SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid=i.inhrelid JOIN pg_class p ON p.oid=i.inhparent
		WHERE p.relname='events' AND p.relnamespace=current_schema()::regnamespace AND c.relname ~ '^events_y[0-9]{4}m[0-9]{2}$'`)
	if err != nil {
		return nil, err
	}
	var names []string
	for rows.Next() {
		var n string
		rows.Scan(&n)
		names = append(names, n)
	}
	rows.Close()
	for _, n := range names {
		var y, m int
		fmt.Sscanf(n, "events_y%04dm%02d", &y, &m)
		end := time.Date(y, time.Month(m), 1, 0, 0, 0, 0, time.UTC).AddDate(0, 1, 0)
		if end.Before(cutoff) {
			if _, err := a.St.DB.Exec(ctx, `DROP TABLE `+n); err != nil {
				return dropped, err
			}
			dropped = append(dropped, n)
		}
	}
	a.St.DB.Exec(ctx, `DELETE FROM events WHERE ts < $1`, cutoff) // trims the boundary month and the default partition
	return dropped, nil
}

// runExclusive runs fn on exactly one manager instance at a time (Postgres advisory lock), so background jobs
// (CRL fetching, retention, certificate renewal) are safe when several managers share one database.
func (a *App) runExclusive(ctx context.Context, lockID int64, fn func(context.Context)) {
	conn, err := a.St.DB.Acquire(ctx)
	if err != nil {
		return
	}
	defer conn.Release()
	var got bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, lockID).Scan(&got); err != nil || !got {
		return
	}
	defer conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, lockID)
	fn(ctx)
}

const (
	lockCRL         int64 = 1001
	lockMaintenance int64 = 1002
)

// ensureEventColumns adds the generated lookup columns (client MAC, AP) to a table partitioned before statistics existed.
// On a large table this rewrites each partition once; fresh installs get the columns at creation time.
func (a *App) ensureEventColumns(ctx context.Context) error {
	for _, s := range []string{
		`ALTER TABLE events ADD COLUMN IF NOT EXISTS client_mac text GENERATED ALWAYS AS (lower(replace(NULLIF(data->>'client_mac',''), '-', ':'))) STORED`,
		`ALTER TABLE events ADD COLUMN IF NOT EXISTS ap text GENERATED ALWAYS AS (data->>'ap') STORED`,
		`CREATE INDEX IF NOT EXISTS events_tenant_mac_ts ON events(tenant_id, client_mac, ts DESC) WHERE client_mac IS NOT NULL`,
	} {
		if _, err := a.St.DB.Exec(ctx, s); err != nil {
			return fmt.Errorf("events columns: %s: %w", s, err)
		}
	}
	return nil
}
