# PostgreSQL with continuous WAL archiving, scheduled backups (pgBackRest) and streaming-replica support.
FROM postgres:17
RUN apt-get update \
 && apt-get install -y --no-install-recommends pgbackrest jq \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /backups /var/log/pgbackrest /tmp/pgbackrest && chown postgres:postgres /backups /var/log/pgbackrest /tmp/pgbackrest
COPY radman-entrypoint.sh backup-scheduler.sh replica-init.sh drill.sh /usr/local/bin/
COPY initdb/ /docker-entrypoint-initdb.d/
RUN chmod +x /usr/local/bin/*.sh /docker-entrypoint-initdb.d/*.sh

# pgBackRest is configured entirely through PGBACKREST_* environment variables (see docker-compose.yml).
ENV PGBACKREST_STANZA=radman \
    PGBACKREST_PG1_PATH=/var/lib/postgresql/data \
    PGBACKREST_REPO1_PATH=/backups \
    PGBACKREST_REPO1_RETENTION_FULL_TYPE=count \
    PGBACKREST_REPO1_RETENTION_FULL=2 \
    PGBACKREST_REPO1_RETENTION_DIFF=7 \
    PGBACKREST_COMPRESS_TYPE=zst \
    PGBACKREST_START_FAST=y \
    PGBACKREST_LOG_PATH=/var/log/pgbackrest \
    PGBACKREST_LOG_LEVEL_CONSOLE=info

ENTRYPOINT ["/usr/local/bin/radman-entrypoint.sh"]
CMD ["postgres", \
     "-c", "wal_level=replica", \
     "-c", "archive_mode=on", \
     "-c", "archive_command=pgbackrest --stanza=radman archive-push %p", \
     "-c", "archive_timeout=60", \
     "-c", "max_wal_senders=10", \
     "-c", "max_replication_slots=10", \
     "-c", "hot_standby=on", \
     "-c", "wal_keep_size=512MB", \
     "-c", "password_encryption=scram-sha-256", \
     "-c", "log_min_duration_statement=1000"]
