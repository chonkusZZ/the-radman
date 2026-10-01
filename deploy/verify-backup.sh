#!/usr/bin/env bash
# Restore drill: proves the backups are usable WITHOUT touching production.
# Restores the newest backup + WAL into a throw-away directory, starts a scratch PostgreSQL on it and runs sanity queries.
# Run it regularly (e.g. weekly from cron) - an untested backup is only a hope.
set -euo pipefail
cd "$(dirname "$0")/.."
DC="docker compose ${COMPOSE_ARGS:-}"
$DC run --rm --no-deps -T --entrypoint bash db -c "gosu postgres /usr/local/bin/drill.sh"
