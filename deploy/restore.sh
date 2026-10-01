#!/usr/bin/env bash
# Restore the database from the pgBackRest repository (docker compose deployment).
#
#   deploy/restore.sh                                   # latest state (replays all archived WAL)
#   deploy/restore.sh --time "2026-10-01 20:31:15+00"   # point in time (e.g. just before an accidental deletion)
#   deploy/restore.sh --list                            # show available backups and the WAL range
#
# Extra compose options (project name, env file) come from COMPOSE_ARGS, e.g.
#   COMPOSE_ARGS="-p rmtest --env-file /tmp/x.env" deploy/restore.sh
set -euo pipefail
cd "$(dirname "$0")/.."
DC="docker compose ${COMPOSE_ARGS:-}"
run_pg() { $DC run --rm --no-deps -T --entrypoint bash db -c "$1"; }

if [ "${1:-}" = "--list" ]; then
  run_pg "gosu postgres pgbackrest info"
  exit 0
fi

TARGET=()
if [ "${1:-}" = "--time" ]; then
  [ -n "${2:-}" ] || { echo "usage: $0 --time 'YYYY-MM-DD HH:MM:SS+00'"; exit 2; }
  TARGET=(--type=time "--target=$2" --target-action=promote)
  echo "Restoring to $2"
else
  echo "Restoring to the latest archived state"
fi

read -r -p "This REPLACES the current database contents. Type 'restore' to continue: " ok
[ "$ok" = "restore" ] || { echo "aborted"; exit 1; }

echo "Stopping manager and database ..."
$DC stop manager db >/dev/null 2>&1 || true
run_pg "chown postgres:postgres /var/lib/postgresql/data && gosu postgres pgbackrest --stanza=radman --delta ${TARGET[*]:-} restore"
echo "Starting database and manager ..."
$DC up -d db manager
echo "Done. Check Platform settings -> Database & backups, and take a fresh full backup once you are happy with the result."
