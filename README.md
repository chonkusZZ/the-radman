# arc's The Rad*MAN* — multi-tenant (MSP) edition

Hosted, multi-tenant RADIUS management for Wi-Fi access points. **EAP-TLS** certificate authentication, **RadSEC** for APs,
Azure Cloud PKI / any CA + CRL, SAML SSO, and per-customer isolation. One platform, many customers ("tenants"), each with
their own sites, access points, nodes, PKI, certificates, logs and users.

```
 MSP staff ─┐                        ┌────────── Manager (1..n instances behind a load balancer) ──────────┐
 Customer   ├─ HTTPS ───────────────▶│ web UI · RBAC · SAML · tenants · per-tenant CAs · CRL fetcher        │
 admins    ─┘                        └───────┬──────────────────────────────────────────────▲──────────────┘
                                             │ SQL                                          │ ONE UDP port (QUIC + mutual TLS)
                         ┌───────────────────▼────────────────────┐          ┌──────────────┴──────────────┐
                         │ PostgreSQL primary ─ WAL archive ─▶ encrypted     │ Site nodes (per tenant site) │
                         │   └─ streaming standby (read replica)  backups    │  RADIUS/EAP-TLS · RadSEC     │
                         └────────────────────────────────────────┘          └──────────────────────────────┘
```

## Editions: one code base, two modes

Standalone and MSP are the **same binary** with a mode switch (`RADMAN_MODE=msp|standalone`, or `--mode`). Every feature exists in both;
only the chrome and the rules around tenants differ. Standalone is simply the MSP engine running with one implicit tenant ("Default").

| | `standalone` | `msp` (default) |
|---|---|---|
| Tenants | one, created automatically, always selected | many, created by global administrators |
| Roles | **Administrator**, **Operator**, **Read-only** | global admin / global read-only / tenant admin / read-only |
| Settings & users | *Settings* (web certificate, SSO, database & backups, branding) and *Users* in the sidebar | *Platform* area (tenants, users, audit, settings) + per-tenant area |
| Single sign-on | one IdP, mapping `group=admin\|operator\|read_only` | platform IdP for staff + each customer's own IdP |
| Everything else | identical: EAP-TLS, RadSEC, PKI/CRL, nodes, policy, logs, backups, HA | identical |

* Standalone roles: *Administrator* manages everything including Settings and Users; *Operator* manages sites, APs, nodes, PKI and certificates;
  *Read-only* can look but never change anything. Multi-tenant pages and routes (`/platform`, `/tenants`, `/t/<slug>/…`, tenant SSO) **do not exist**
  in standalone mode.
* **Moving between editions needs no migration.** Standalone → MSP: start with `RADMAN_MODE=msp`; your data is already the "Default" tenant, administrators
  stay global administrators, operators become tenant administrators. MSP → standalone works while the database holds exactly one tenant;
  with several the manager refuses to start in standalone mode rather than hide customers.
* Docker: `docker compose -f docker-compose.yml -f docker-compose.standalone.yml up -d` (or `RADMAN_MODE=standalone` in `.env`).
* Tests: `make test-all` runs the whole suite once per edition (`RADMAN_TEST_MODE`), plus edition-specific tests.

## Stats

*Stats* (every role that can read a tenant; both editions) has three tabs:

* **Overview** — accepted vs rejected authentications and a rejects-only chart, **per hour (48 h) / per day (30 days) / per month (12 months)**,
  filterable by site and time zone, with reject-rate, active/new clients, rejects broken down by reason (revoked, expired, untrusted CA, policy,
  no certificate, client distrusts the server certificate, …) and the latest rejects. Charts are server-rendered SVG (no JavaScript library) with tooltips.
* **Clients** — one row per client MAC: **first seen, last seen, how many times it connected** (successful authentications), rejects, accounting
  sessions, **roams**, last AP/SSID and certificate subject; search, filters (new today/this week, roamed, has rejects, private MAC) and sorting.
  A client's page shows its AP history, data used (30 days) and recent activity with **roam** markers.
* **Reports** — **AP usage** (accepted/rejected, unique clients, sessions, upload/download, session time per AP), **top talkers** (clients ranked by
  data), **rejected authentications**, and **clients**; each as **CSV** (UTF-8 with BOM for Excel; formula-injection safe) or a **printable view**
  (browser *Save as PDF*), for a chosen site and period (24 h … 90 days or a custom range).

How it stays fast and long-lived: ingest folds events into rollup tables (hourly counters, per-client history) in the same transaction as the events,
so graphs and client history survive for **Statistics retention** (default 400 days) even after the raw events are purged (**Event retention**, default
90 days — usage/top-talker/reject reports are built from raw events and say so when clamped). Retried deliveries are never double counted, and
existing events are replayed into the rollups once on upgrade (tested to match live ingestion exactly).

Definitions: a **connect** = successful authentication; a **roam** = a connection (successful auth or accounting start) on a different AP within one hour of
the client's previous one; clients are identified by MAC, so phones with *private Wi-Fi address* appear under each private address. Upload/download are from
the client's point of view and include Acct-*-Gigawords for sessions over 4 GB (**redeploy the node binary** to capture gigawords; older nodes undercount such
sessions). Time zone is set under Settings → General.

## RADIUS server certificate names (CN / SANs) per node

When creating a node you can give the names devices will use to reach it, e.g. `radius.example.com, 10.1.0.5` (host names, wildcards and IPv4/IPv6
addresses, comma/space separated). The node then gets **its own server certificate** from the tenant's EAP CA: the first name is the **CN**, and **all
names are subject alternative names** (what modern supplicants check). It is also what access points see over RadSEC. Leave the field empty to use the site's
certificate. Change or clear the names later on the node's page (the node picks the new certificate up at its next check-in). These certificates renew
automatically with the same names. Devices must trust the tenant's EAP CA (*Server certificates → Download EAP CA*) and, if they validate the server name,
the name configured on the device must be one of the names listed.

## Roles (RBAC)

| Role | Scope | Can do |
|---|---|---|
| **Global administrator** | whole platform | everything: create/suspend/delete tenants, quotas, any tenant's data, platform users, web certificate, SSO, branding, database & backup tools |
| **Global read-only** | whole platform | *see* every tenant and the platform settings; change nothing |
| **Tenant administrator** | tenants they are a member of | full control of **only** those tenants: sites, APs, nodes, PKI, server certificates, RadSEC, policy, and that tenant's users |
| **Read-only** | tenants they are a member of | view sites, nodes, PKI, logs; **no** changes, no AP secrets, no node enrollment tokens, no user list |

A person can be a member of several tenants with a different role in each (typical for an MSP engineer), and the UI keeps one
tenant "open" at a time. A **suspended** tenant is frozen for its own users (read-only); the provider can still change it, and
the site nodes keep authenticating from their cached configuration.

Isolation is enforced server-side on every request (a resource id from another tenant is indistinguishable from a missing one),
and each tenant gets its **own private EAP-server and RadSEC certificate authorities**, so one customer's devices or APs never
trust anything issued for another. The permission matrix, cross-tenant access attempts, quota/suspension handling and tenant deletion
are covered by automated tests (and I mutation-checked that the tests fail when the checks are removed).

Tenant quotas (sites / APs / nodes, 0 = unlimited) are set per tenant.

## Quick start (Docker Compose)

```bash
cp .env.example .env            # set RADMAN_DB_PASSWORD and BACKUP_PASSPHRASE
docker compose up -d
docker compose logs manager | grep "setup token"
# open https://<host>/ -> create the first global administrator
# Platform -> Tenants -> New tenant -> add its administrators -> Open the tenant and build sites
```
Ports: **443/tcp** (UI), 80/tcp (redirect), **7843/udp** (all site nodes). Everything else — the node download, enrollment, RadSEC
generator, PKI, logs — works as before, now inside a tenant.

### Upgrading from the single-tenant version
Just start the new manager against the existing database. On first start it **migrates in place** (idempotent): existing data moves
into a tenant called **Default**; old *admin* users become **global administrators**, *operators* become tenant administrators and
*viewers* read-only members of Default; the old EAP/RadSec CAs become Default's CAs (already-issued certificates keep working);
the events table is converted to monthly partitions; site/PKI names become unique per tenant. This path is tested against a schema
captured from the previous release. **Take a backup first** (below).

## Single sign-on (SAML / Entra ID) — platform **and** per tenant

Two independent levels, both SAML 2.0 (built with Entra ID in mind):

**1. Platform SSO — your own staff** (*Platform settings → Single sign-on*, global administrators). Map your IdP's groups to roles:
```
<group-id>=global_admin
<group-id>=global_readonly
<group-id>=tenant_admin@acme-ltd        # tenant slug shown on the tenant page
<group-id>=read_only@acme-ltd
```

**2. Tenant SSO — each customer's own identity provider** (*tenant → Single sign-on*, by the **tenant administrator**, or by a global
administrator working inside the tenant — the tenant page has a shortcut). Each tenant gets:
* its **own service-provider identity**: Entity ID / ACS / metadata under `/t/<slug>/saml/…` and its own SP key pair, so a customer registers
  *their* application in *their* Entra ID;
* its **own sign-in page** `https://<host>/t/<slug>/login` to give to users, and optional **e-mail discovery** on the main login page
  (type your address → sent to your organisation's IdP);
* its own **group → role** mapping (`group-id=tenant_admin` / `read_only`), an optional "everyone from my IdP is read-only" default,
  and an option to **disable local passwords** for the tenant's users.

Security properties of tenant SSO (all covered by automated attack tests, with the key checks mutation-tested):
* A tenant's IdP can only ever grant access **to that tenant** — never a platform role, never another tenant.
* **Accounts are bound to the IdP that created them.** A customer IdP that asserts the e-mail of an existing local user, a platform
  staff member, or another customer's user is refused and the account is left untouched.
* An assertion minted for one tenant is rejected at another tenant's endpoint or the platform's.
* IdP metadata URLs are fetched through a guarded client: loopback, link-local and (for tenants) private ranges are refused, so a tenant
  administrator can't use the feature to probe the platform's internal network (or a cloud metadata service).
* **E-mail domains** (used for discovery and to restrict which addresses an IdP may sign in) can only be set by a global administrator, and
  each domain belongs to one tenant — otherwise a tenant could claim someone else's domain and intercept their sign-ins.
* Deleting a tenant removes its IdP configuration, SP key, domains and the accounts its IdP created.

---

# Database: scaling, backups and resilience

**Recommendation in one paragraph.** Keep PostgreSQL as the single system of record and make it *recoverable* first, *highly
available* second. (1) Continuous WAL archiving + encrypted base backups off the database host give you point-in-time recovery from
disk loss, corruption or an operator mistake — the failure modes that actually hurt MSPs. (2) A streaming standby gives fast manual
failover and a place to run heavy reads. (3) For *automatic* failover, don't hand-roll it: use your cloud's zone-redundant managed
PostgreSQL (Azure Database for PostgreSQL – Flexible Server with zone-redundant HA, AWS RDS/Aurora Multi-AZ, …) or Patroni /
CloudNativePG; the manager only needs one DSN (plus an optional read-only DSN). (4) Test restores on a schedule.

### What is included
| Capability | How |
|---|---|
| **Point-in-time recovery** | `archive_command` ships every WAL segment (at most every 60 s) to a pgBackRest repository: RPO ≈ 1 minute for loss of the database host |
| **Scheduled backups** | full weekly, differential daily (+ first full at install), plus a nightly logical `pg_dump` for portable/cross-version restores; retention configurable |
| **Encrypted, off-site** | repository is AES-256 encrypted; point it at **S3 / MinIO / Azure Blob / GCS** with `PGBACKREST_REPO1_*` env vars (see `docker-compose.yml`) or bind-mount a separate disk with `BACKUP_PATH` |
| **Visibility** | *Platform settings → Database & backups*: last good backup, run history, WAL-archive health, replication lag, pool use, partition sizes |
| **Master-key recovery kit** | the encrypted database is useless without `master.key`; export an **encrypted kit** from the same page and store it away from the backups (or supply the key via `RADMAN_MASTER_KEY` from a secret manager) |
| **Streaming standby** | `docker compose --profile replica up -d` (needs `RADMAN_REPLICATION_PASSWORD`); set `RADMAN_DATABASE_RO_URL` so logs/dashboards read from it |
| **Restore & drill** | `deploy/restore.sh` (latest or `--time`), `deploy/verify-backup.sh` (restores into a scratch server and queries it) |
| **Scaling the app tier** | managers are stateless: sessions, web-certificate cache (Let's Encrypt) and settings live in the database; background jobs (CRL fetch, retention, renewals) run on exactly one instance via advisory locks; the UDP node port can be load-balanced |
| **Scaling the data** | `events` (auth + accounting) is **partitioned monthly**; retention drops whole partitions instantly; ingest is idempotent per node/sequence |

### Verified here (not just written)
* Destroyed the database volume and restored **to the second before an accidental `DROP TABLE`** from the encrypted repository — all rows back.
* Restore drill: newest backup + WAL replayed into a scratch server showed tenants/sites/users created long after the base backup.
* Standby streams, is read-only, and **promotes** (failover) and accepts writes.
* Two manager instances on one database share sessions and the same web certificate (key via `RADMAN_MASTER_KEY`).
* Legacy single-tenant → multi-tenant migration and monthly-partition conversion, run twice (idempotent), with data checks.

### Runbook
```bash
# What backups exist?                          deploy/restore.sh --list
# Prove they work (weekly cron):               deploy/verify-backup.sh
# Disaster / mistake -> point in time:         deploy/restore.sh --time "2026-10-01 20:31:15+00"
# After ANY restore or failover: take a fresh full backup (new timeline):
#     docker compose exec db gosu postgres pgbackrest --stanza=radman --type=full backup
# Failover to the standby (primary lost):      docker compose exec -u postgres db-replica pg_ctl promote -D /var/lib/postgresql/data
#     then point RADMAN_DATABASE_URL at it and restart the manager(s); build a new standby from it.
```
Operational notes
* **Back up the backup passphrase and the master key separately from the backups.** Without the passphrase the repository cannot be read; without the master key the restored secrets cannot be decrypted.
* Monitor: the *Database & backups* page (or alert on `backup_runs.status='failed'`, `pg_stat_archiver.failed_count`, replica lag), disk on the repository, and the age of the last good backup.
* Replication is **asynchronous** (a few ms of lag normally; a failover can lose the last moments). If you need zero loss, configure synchronous replication on a managed service or Patroni.
* A standby cloned from a primary that was itself PITR-restored must not inherit its `recovery_target_*` settings — `replica-init.sh` strips them (this bit me during testing).
* PgBouncer: fine for many manager instances in *session* mode; the advisory-lock jobs are incompatible with transaction pooling. A single manager needs no pooler (`?pool_max_conns=` on the URL sets its pool).

### Capacity guidance (qualitative)
Config reads (node check-ins, UI) are tiny; the growth is the events table. Partitioning keeps queries and retention cheap; add a read replica
before sharding. Revisit when a single month's partition no longer fits comfortably in RAM/cache, or when write volume approaches what one
primary handles — at that point split by tenant group (separate platform instance) rather than re-architecting.

---

## Everything from the single-tenant release still applies
EAP-TLS (TLS 1.2/1.3, verified with `wpa_supplicant`), CRL / Azure Cloud PKI profiles with fail-open/closed, per-site policy rules and
VLANs, nodes that keep working without the manager, one UDP port (QUIC + mutual TLS), automatic 90-day node certificates, RadSEC with
browser-generated keys, web certificate options (Let's Encrypt / own / CSR), SVG logo, and the arc systems colour scheme. Build:
`make` (manager + node binaries for 6 platforms); tests: `RADMAN_TEST_DB=postgres://user:pw@host/postgres go test ./...`.

## Limitations / next steps
* One platform logo (no per-tenant branding yet). Domain ownership for e-mail discovery is asserted by the platform operator, not verified automatically (e.g. via DNS).
* No automated failover shipped — see the recommendation above; promotion of the standby is manual.
* Events on the read replica can lag slightly behind the primary.
* Node tokens/RadSEC/EAP behaviour is unchanged and still unverified against real APs and a real Entra/Cloud PKI tenant.
