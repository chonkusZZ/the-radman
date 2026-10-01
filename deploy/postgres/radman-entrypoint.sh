#!/bin/bash
# Wrapper around the official entrypoint: optionally bootstraps a standby, and starts the backup scheduler.
set -e
if [ "$(id -u)" = "0" ]; then
  mkdir -p /backups /var/log/pgbackrest
  chown postgres:postgres /backups /var/log/pgbackrest 2>/dev/null || true
fi

# Standby mode: clone the primary on first start instead of running initdb.
if [ "${REPLICA_OF:-}" != "" ] && [ ! -s "$PGDATA/PG_VERSION" ]; then
  /usr/local/bin/replica-init.sh
fi

# Backups run only on the primary (BACKUP_ENABLED=false for standbys).
if [ "${BACKUP_ENABLED:-true}" = "true" ] && [ "${REPLICA_OF:-}" = "" ]; then
  nohup gosu postgres /usr/local/bin/backup-scheduler.sh >> /var/log/pgbackrest/scheduler.log 2>&1 &
fi

exec docker-entrypoint.sh "$@"
