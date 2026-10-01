#!/bin/bash
# Creates the replication role and lets standbys connect (runs once, on first initialisation of a primary).
set -e
if [ -n "${REPLICATION_PASSWORD:-}" ]; then
  psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" <<SQL
CREATE ROLE replicator WITH REPLICATION LOGIN PASSWORD '${REPLICATION_PASSWORD}';
SQL
  echo "host replication replicator all scram-sha-256" >> "$PGDATA/pg_hba.conf"
fi
