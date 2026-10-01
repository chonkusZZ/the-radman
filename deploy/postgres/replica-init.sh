#!/bin/bash
# Clone the primary into $PGDATA as a streaming standby (replication slot keeps the primary from discarding needed WAL).
set -e
: "${REPLICA_OF:?}" "${REPLICATION_PASSWORD:?}"
SLOT="${REPLICA_SLOT:-replica_$(hostname | tr -c 'a-z0-9\n' '_')}"
echo "replica-init: waiting for primary $REPLICA_OF ..."
until PGPASSWORD="$REPLICATION_PASSWORD" pg_isready -h "$REPLICA_OF" -U replicator >/dev/null 2>&1; do sleep 2; done
mkdir -p "$PGDATA" && chown postgres:postgres "$PGDATA" && chmod 700 "$PGDATA"
gosu postgres bash -c "PGPASSWORD='$REPLICATION_PASSWORD' pg_basebackup -h '$REPLICA_OF' -U replicator -D '$PGDATA' -R -X stream -C -S '$SLOT' --checkpoint=fast -P"
# A primary that was restored with point-in-time recovery keeps its recovery_target_* / restore_command settings in
# postgresql.auto.conf; a standby must never inherit them (it would stop replaying at that target and promote itself).
sed -i -E '/^(recovery_target[a-z_]*|restore_command)[[:space:]]*=/d' "$PGDATA/postgresql.auto.conf"
echo "replica-init: standby cloned (slot $SLOT)"
