#!/bin/bash
# Backup scheduler for the primary. Runs as the postgres user next to the database.
#   * stanza creation + a first full backup as soon as the database is up
#   * daily differential, weekly full, plus a nightly logical dump (pg_dump) for portable restores
#   * every run is recorded in the backup_runs table so the manager UI can show it
# Continuous WAL archiving (archive_command) provides point-in-time recovery between backups.
set -u
DB="${POSTGRES_DB:-postgres}"
HOUR="${BACKUP_HOUR:-1}"            # local hour of the daily run
FULL_DAY="${BACKUP_FULL_DAY:-0}"    # 0 = Sunday
LOGICAL_KEEP_DAYS="${BACKUP_LOGICAL_KEEP_DAYS:-14}"
LOGICAL_DIR=/backups/logical
export PGHOST=/var/run/postgresql PGUSER="${POSTGRES_USER:-postgres}"
log() { echo "$(date -u +%FT%TZ) scheduler: $*"; }
sql() { psql -qAtX -d "$DB" -c "$1" 2>/dev/null; }

until pg_isready -q -h 127.0.0.1 -d "$DB"; do sleep 3; done   # TCP only comes up on the final server, not the init-time one
sleep 5
log "database is up"

ensure_stanza() {
  pgbackrest stanza-create >/dev/null 2>&1 || pgbackrest stanza-create 2>&1 | tail -3
}

record() { # kind
  sql "INSERT INTO backup_runs(kind) VALUES('$1') RETURNING id"
}
finish() { # id status detail size
  sql "UPDATE backup_runs SET finished_at=now(), status='$2', detail=\$q\$$3\$q\$, size_bytes=${4:-NULL} WHERE id=$1" >/dev/null
}

run_backup() { # type
  local type="$1" id out rc size label
  id=$(record "$type")
  log "starting $type backup (run $id)"
  out=$(pgbackrest --type="$type" backup 2>&1); rc=$?
  size=$(pgbackrest info --output=json 2>/dev/null | jq -r '.[0].backup[-1].info.repository.delta // empty' 2>/dev/null)
  label=$(pgbackrest info --output=json 2>/dev/null | jq -r '.[0].backup[-1].label // empty' 2>/dev/null)
  if [ $rc -eq 0 ]; then finish "$id" ok "pgBackRest backup ${label:-?}" "${size:-NULL}"; log "$type backup ok ($label)"
  else finish "$id" failed "$(echo "$out" | tail -5 | tr '\n' ' ')"; log "$type backup FAILED: $out"; fi
  return $rc
}

run_logical() {
  local id f rc out
  mkdir -p "$LOGICAL_DIR"
  id=$(record logical)
  f="$LOGICAL_DIR/${DB}-$(date -u +%Y%m%dT%H%M%SZ).dump"
  out=$(pg_dump -Fc -d "$DB" -f "$f" 2>&1); rc=$?
  if [ $rc -eq 0 ]; then finish "$id" ok "$f" "$(stat -c %s "$f")"; else finish "$id" failed "$out"; rm -f "$f"; fi
  find "$LOGICAL_DIR" -name '*.dump' -mtime +"$LOGICAL_KEEP_DAYS" -delete 2>/dev/null
}

# same definition as the manager's schema; whichever starts first creates it
sql "CREATE TABLE IF NOT EXISTS backup_runs (id bigserial PRIMARY KEY, started_at timestamptz NOT NULL DEFAULT now(), finished_at timestamptz, kind text NOT NULL, status text NOT NULL DEFAULT 'running', detail text NOT NULL DEFAULT '', size_bytes bigint)" >/dev/null
ensure_stanza
pgbackrest check >/dev/null 2>&1 || log "pgbackrest check reported a problem (archiving not working yet?)"
if ! pgbackrest info --output=json 2>/dev/null | jq -e '.[0].backup | length > 0' >/dev/null 2>&1; then run_backup full; fi

last=""
while true; do
  now_day=$(date +%F)
  if [ "$(date +%-H)" = "$HOUR" ] && [ "$last" != "$now_day" ]; then
    last="$now_day"
    if [ "$(date +%w)" = "$FULL_DAY" ]; then run_backup full; else run_backup diff; fi
    run_logical
    pgbackrest check >/dev/null 2>&1 || log "pgbackrest check FAILED after backup"
  fi
  sleep 60
done
