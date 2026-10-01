#!/bin/bash
# Restore drill (runs as the postgres user): newest backup + WAL -> scratch directory -> scratch server -> sanity queries.
set -e
D=/tmp/drill
rm -rf "$D"; mkdir -p "$D"; chmod 700 "$D"
pgbackrest --stanza=radman --pg1-path="$D" restore
if ! pg_ctl -D "$D" -l /tmp/drill.log -o "-p 5499 -c archive_mode=off -c listen_addresses= -c unix_socket_directories=/tmp" -w -t 120 start >/dev/null; then
  echo "scratch server failed to start:"; tail -20 /tmp/drill.log; exit 1
fi
# the server accepts read-only connections while it still replays WAL: wait until recovery has finished
for i in $(seq 1 300); do
  [ "$(psql -h /tmp -p 5499 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -qAt -c 'select pg_is_in_recovery()' 2>/dev/null)" = "f" ] && break
  sleep 1
done
psql -h /tmp -p 5499 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -qAt <<'SQL'
select 'tenants: '||count(*) from tenants;
select 'sites:   '||count(*) from sites;
select 'users:   '||count(*) from users;
select 'events:  '||count(*) from events;
SQL
pg_ctl -D "$D" -m fast stop >/dev/null
rm -rf "$D"
echo "RESTORE DRILL OK"
