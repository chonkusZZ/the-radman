package manager

import (
	"context"
	"time"
)

// DBHealth is the operational picture of the database shown under Platform settings -> Database & backups.
type DBHealth struct {
	Version      string
	SizeBytes    int64
	InRecovery   bool
	Connections  int
	MaxConns     int
	PoolInUse    int32
	PoolTotal    int32
	Replicas     []ReplicaInfo
	Archiver     ArchiverInfo
	ArchiveMode  string
	Backups      []BackupRun
	LastGood     *BackupRun
	Partitions   []PartitionInfo
	Tables       []TableInfo
	HasReplicaRO bool
	KeyFromEnv   bool
	Errors       []string
}

type ReplicaInfo struct {
	Addr, State, SyncState string
	LagBytes               int64
	ReplayLag              string
}

type ArchiverInfo struct {
	Archived, Failed int64
	LastArchived     *time.Time
	LastFailed       *time.Time
	LastArchivedWAL  string
	LastFailedWAL    string
}

type BackupRun struct {
	Kind, Status, Detail string
	Started              time.Time
	Finished             *time.Time
	Size                 *int64
}

type PartitionInfo struct {
	Name  string
	Rows  int64
	Bytes int64
}

type TableInfo struct {
	Name  string
	Bytes int64
}

func (a *App) DBHealth(ctx context.Context) *DBHealth {
	h := &DBHealth{}
	db := a.St.DB
	note := func(what string, err error) {
		if err != nil {
			h.Errors = append(h.Errors, what+": "+err.Error())
		}
	}
	note("version", db.QueryRow(ctx, `SELECT version(), pg_database_size(current_database()), pg_is_in_recovery(), current_setting('max_connections')::int, (SELECT count(*) FROM pg_stat_activity WHERE datname=current_database())`).
		Scan(&h.Version, &h.SizeBytes, &h.InRecovery, &h.MaxConns, &h.Connections))
	st := db.Stat()
	h.PoolInUse, h.PoolTotal = st.AcquiredConns(), st.TotalConns()
	h.HasReplicaRO = a.St.RO != a.St.DB
	h.KeyFromEnv = keyFromEnv()

	db.QueryRow(ctx, `SELECT current_setting('archive_mode')`).Scan(&h.ArchiveMode)
	db.QueryRow(ctx, `SELECT archived_count, failed_count, last_archived_time, last_failed_time, COALESCE(last_archived_wal,''), COALESCE(last_failed_wal,'') FROM pg_stat_archiver`).
		Scan(&h.Archiver.Archived, &h.Archiver.Failed, &h.Archiver.LastArchived, &h.Archiver.LastFailed, &h.Archiver.LastArchivedWAL, &h.Archiver.LastFailedWAL)

	if rows, err := db.Query(ctx, `SELECT COALESCE(client_addr::text,''), state, COALESCE(sync_state,''), COALESCE(pg_wal_lsn_diff(pg_current_wal_lsn(), replay_lsn),0)::bigint, COALESCE(replay_lag::text,'') FROM pg_stat_replication`); err == nil {
		for rows.Next() {
			var r ReplicaInfo
			rows.Scan(&r.Addr, &r.State, &r.SyncState, &r.LagBytes, &r.ReplayLag)
			h.Replicas = append(h.Replicas, r)
		}
		rows.Close()
	}
	if rows, err := db.Query(ctx, `SELECT kind, status, detail, started_at, finished_at, size_bytes FROM backup_runs ORDER BY id DESC LIMIT 15`); err == nil {
		for rows.Next() {
			var b BackupRun
			rows.Scan(&b.Kind, &b.Status, &b.Detail, &b.Started, &b.Finished, &b.Size)
			h.Backups = append(h.Backups, b)
		}
		rows.Close()
	}
	var lg BackupRun
	if err := db.QueryRow(ctx, `SELECT kind, status, detail, started_at, finished_at, size_bytes FROM backup_runs WHERE status='ok' ORDER BY id DESC LIMIT 1`).Scan(&lg.Kind, &lg.Status, &lg.Detail, &lg.Started, &lg.Finished, &lg.Size); err == nil {
		h.LastGood = &lg
	}
	if rows, err := db.Query(ctx, `SELECT c.relname, COALESCE(c.reltuples,0)::bigint, pg_total_relation_size(c.oid) FROM pg_inherits i JOIN pg_class c ON c.oid=i.inhrelid JOIN pg_class p ON p.oid=i.inhparent
		WHERE p.relname='events' ORDER BY c.relname`); err == nil {
		for rows.Next() {
			var p PartitionInfo
			rows.Scan(&p.Name, &p.Rows, &p.Bytes)
			h.Partitions = append(h.Partitions, p)
		}
		rows.Close()
	}
	if rows, err := db.Query(ctx, `SELECT relname, pg_total_relation_size(c.oid) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
		WHERE n.nspname=current_schema() AND c.relkind='r' AND c.relispartition=false ORDER BY 2 DESC LIMIT 8`); err == nil {
		for rows.Next() {
			var t TableInfo
			rows.Scan(&t.Name, &t.Bytes)
			h.Tables = append(h.Tables, t)
		}
		rows.Close()
	}
	return h
}
