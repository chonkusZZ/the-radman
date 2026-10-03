CREATE TABLE IF NOT EXISTS settings (key text PRIMARY KEY, value jsonb NOT NULL);
CREATE TABLE IF NOT EXISTS secrets  (key text PRIMARY KEY, value text NOT NULL);

CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text UNIQUE NOT NULL,
  name text NOT NULL DEFAULT '',
  password_hash text NOT NULL DEFAULT '',
  role text NOT NULL DEFAULT 'viewer',
  totp_secret text NOT NULL DEFAULT '',
  totp_enabled boolean NOT NULL DEFAULT false,
  sso boolean NOT NULL DEFAULT false,
  disabled boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_login timestamptz
);

CREATE TABLE IF NOT EXISTS sessions (
  id text PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf text NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS pki_profiles (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text UNIQUE NOT NULL,
  kind text NOT NULL DEFAULT 'generic',
  ca_pem text NOT NULL,
  crl_urls text[] NOT NULL DEFAULT '{}',
  stale_policy text NOT NULL DEFAULT 'fail_closed',
  stale_grace_hours int NOT NULL DEFAULT 24,
  notes text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS crl_cache (
  url text PRIMARY KEY,
  der bytea,
  this_update timestamptz,
  next_update timestamptz,
  fetched_at timestamptz,
  last_attempt timestamptz,
  last_error text NOT NULL DEFAULT '',
  revoked_count int NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS eap_certs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  source text NOT NULL,
  cert_pem text NOT NULL,
  key_enc text NOT NULL,
  not_after timestamptz NOT NULL,
  dns_names text[] NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sites (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text UNIQUE NOT NULL,
  description text NOT NULL DEFAULT '',
  eap_cert_id uuid REFERENCES eap_certs(id) ON DELETE SET NULL,
  policy jsonb NOT NULL DEFAULT '{"default_action":"allow","default_vlan":"","rules":[]}',
  auth_port int NOT NULL DEFAULT 1812,
  acct_port int NOT NULL DEFAULT 1813,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS site_pki (
  site_id uuid NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  pki_id uuid NOT NULL REFERENCES pki_profiles(id) ON DELETE RESTRICT,
  PRIMARY KEY (site_id, pki_id)
);

CREATE TABLE IF NOT EXISTS aps (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  site_id uuid NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  name text NOT NULL,
  addr text NOT NULL,
  secret_enc text NOT NULL,
  vendor text NOT NULL DEFAULT '',
  notes text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (site_id, name)
);

CREATE TABLE IF NOT EXISTS nodes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  site_id uuid NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  name text NOT NULL,
  status text NOT NULL DEFAULT 'pending',
  token_hash text NOT NULL DEFAULT '',
  token_enc text NOT NULL DEFAULT '',
  token_expires timestamptz,
  cert_serial text NOT NULL DEFAULT '',
  prev_cert_serial text NOT NULL DEFAULT '',
  cert_not_after timestamptz,
  last_seen timestamptz,
  last_addr text NOT NULL DEFAULT '',
  version text NOT NULL DEFAULT '',
  os text NOT NULL DEFAULT '',
  hostname text NOT NULL DEFAULT '',
  config_hash text NOT NULL DEFAULT '',
  stats jsonb NOT NULL DEFAULT '{}',
  crl_status jsonb NOT NULL DEFAULT '[]',
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS nodes_token ON nodes(token_hash) WHERE token_hash <> '';

CREATE TABLE IF NOT EXISTS events (
  id bigserial PRIMARY KEY,
  node_id uuid NOT NULL,
  site_id uuid NOT NULL,
  seq bigint NOT NULL,
  ts timestamptz NOT NULL,
  kind text NOT NULL,
  data jsonb NOT NULL,
  UNIQUE (node_id, seq)
);
CREATE INDEX IF NOT EXISTS events_kind_ts ON events(kind, ts DESC);
CREATE INDEX IF NOT EXISTS events_site_ts ON events(site_id, ts DESC);

CREATE TABLE IF NOT EXISTS audit (
  id bigserial PRIMARY KEY,
  ts timestamptz NOT NULL DEFAULT now(),
  actor text NOT NULL,
  action text NOT NULL,
  detail text NOT NULL DEFAULT ''
);

-- RadSec (RADIUS over TLS) for access points
ALTER TABLE sites ADD COLUMN IF NOT EXISTS radsec_port int NOT NULL DEFAULT 0;
CREATE TABLE IF NOT EXISTS radsec_certs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  ap_id uuid NOT NULL REFERENCES aps(id) ON DELETE CASCADE,
  serial text NOT NULL,
  subject text NOT NULL,
  algo text NOT NULL,
  not_after timestamptz NOT NULL,
  created_by text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz
);
CREATE INDEX IF NOT EXISTS radsec_certs_ap ON radsec_certs(ap_id);

-- ===== Multi-tenancy (MSP) =====
CREATE TABLE IF NOT EXISTS tenants (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text UNIQUE NOT NULL,
  slug text UNIQUE NOT NULL,
  status text NOT NULL DEFAULT 'active',          -- active | suspended
  max_sites int NOT NULL DEFAULT 0,               -- 0 = unlimited
  max_nodes int NOT NULL DEFAULT 0,
  max_aps int NOT NULL DEFAULT 0,
  notes text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE users ADD COLUMN IF NOT EXISTS platform_role text NOT NULL DEFAULT '';  -- '' | global_admin | global_readonly
CREATE TABLE IF NOT EXISTS memberships (
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  role text NOT NULL CHECK (role IN ('tenant_admin','read_only')),
  source text NOT NULL DEFAULT 'manual',          -- manual | sso (re-synced at every SSO login)
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, tenant_id)
);
CREATE INDEX IF NOT EXISTS memberships_tenant ON memberships(tenant_id);

ALTER TABLE sessions     ADD COLUMN IF NOT EXISTS tenant_id uuid REFERENCES tenants(id) ON DELETE SET NULL;
ALTER TABLE sites        ADD COLUMN IF NOT EXISTS tenant_id uuid REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE pki_profiles ADD COLUMN IF NOT EXISTS tenant_id uuid REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE eap_certs    ADD COLUMN IF NOT EXISTS tenant_id uuid REFERENCES tenants(id) ON DELETE CASCADE;
ALTER TABLE events       ADD COLUMN IF NOT EXISTS tenant_id uuid;
ALTER TABLE audit        ADD COLUMN IF NOT EXISTS tenant_id uuid;
CREATE INDEX IF NOT EXISTS sites_tenant ON sites(tenant_id);
CREATE INDEX IF NOT EXISTS pki_tenant ON pki_profiles(tenant_id);
CREATE INDEX IF NOT EXISTS eap_tenant ON eap_certs(tenant_id);
CREATE INDEX IF NOT EXISTS audit_tenant ON audit(tenant_id, id DESC);

-- ===== Operations =====
CREATE TABLE IF NOT EXISTS backup_runs (          -- written by the backup scheduler (deploy/postgres)
  id bigserial PRIMARY KEY,
  started_at timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz,
  kind text NOT NULL,                              -- full | diff | incr | logical
  status text NOT NULL DEFAULT 'running',          -- running | ok | failed
  detail text NOT NULL DEFAULT '',
  size_bytes bigint
);
CREATE TABLE IF NOT EXISTS acme_cache (key text PRIMARY KEY, data bytea NOT NULL, updated_at timestamptz NOT NULL DEFAULT now());

-- ===== Per-tenant single sign-on =====
-- An SSO user is bound to the identity provider that created the account ('platform' or a tenant id), so a customer's
-- IdP can never sign in as, or modify, someone who belongs to another IdP or to the platform.
ALTER TABLE users ADD COLUMN IF NOT EXISTS idp text NOT NULL DEFAULT '';
UPDATE users SET idp='platform' WHERE sso AND idp='';
-- e-mail domains a tenant's IdP serves (home-realm discovery); a domain can belong to one tenant only
CREATE TABLE IF NOT EXISTS tenant_sso_domains (
  domain text PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE
);

-- ===== Statistics rollups (kept long after the raw events are purged) =====
CREATE TABLE IF NOT EXISTS stats_hourly (
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  site_id uuid NOT NULL,
  hour timestamptz NOT NULL,
  accepts bigint NOT NULL DEFAULT 0,
  rejects bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (tenant_id, site_id, hour)
);
CREATE INDEX IF NOT EXISTS stats_hourly_tenant_hour ON stats_hourly(tenant_id, hour);
CREATE TABLE IF NOT EXISTS stats_reasons (       -- rejected authentications by category
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  site_id uuid NOT NULL,
  hour timestamptz NOT NULL,
  category text NOT NULL,
  n bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (tenant_id, site_id, hour, category)
);
CREATE INDEX IF NOT EXISTS stats_reasons_tenant_hour ON stats_reasons(tenant_id, hour);
CREATE TABLE IF NOT EXISTS client_stats (        -- one row per client (MAC) per tenant
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  mac text NOT NULL,
  first_seen timestamptz NOT NULL,
  last_seen timestamptz NOT NULL,
  accepts bigint NOT NULL DEFAULT 0,             -- successful authentications ("connects")
  rejects bigint NOT NULL DEFAULT 0,
  sessions bigint NOT NULL DEFAULT 0,            -- accounting session starts
  roams bigint NOT NULL DEFAULT 0,
  last_ap text NOT NULL DEFAULT '',              -- AP of the most recent connection event
  last_ap_at timestamptz,
  last_ssid text NOT NULL DEFAULT '',
  last_subject text NOT NULL DEFAULT '',         -- certificate subject of the last successful authentication
  PRIMARY KEY (tenant_id, mac)
);
CREATE INDEX IF NOT EXISTS client_stats_last ON client_stats(tenant_id, last_seen DESC);
CREATE INDEX IF NOT EXISTS client_stats_first ON client_stats(tenant_id, first_seen DESC);
CREATE TABLE IF NOT EXISTS client_aps (
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  mac text NOT NULL,
  ap text NOT NULL,
  first_seen timestamptz NOT NULL,
  last_seen timestamptz NOT NULL,
  accepts bigint NOT NULL DEFAULT 0,
  rejects bigint NOT NULL DEFAULT 0,
  sessions bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (tenant_id, mac, ap)
);

-- ===== Per-node RADIUS server certificate names =====
-- A node may carry its own server certificate (CN + SANs chosen by the administrator); otherwise it uses its site's certificate.
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS eap_names text[] NOT NULL DEFAULT '{}';
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS eap_cert_pem text NOT NULL DEFAULT '';
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS eap_key_enc text NOT NULL DEFAULT '';
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS eap_not_after timestamptz;

-- Node logging: level and age pushed to the node in its config; log bundles collected on demand at the next check-in.
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS log_level text NOT NULL DEFAULT 'info';
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS log_retention_days int NOT NULL DEFAULT 30;

CREATE TABLE IF NOT EXISTS node_log_bundles (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  node_id uuid NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  requested_by text NOT NULL DEFAULT '',
  requested_at timestamptz NOT NULL DEFAULT now(),
  status text NOT NULL DEFAULT 'requested', -- requested | receiving | ready | failed
  chunks int NOT NULL DEFAULT 0,
  size bigint NOT NULL DEFAULT 0,
  error text NOT NULL DEFAULT '',
  completed_at timestamptz
);
CREATE INDEX IF NOT EXISTS node_log_bundles_node ON node_log_bundles(node_id, requested_at DESC);

CREATE TABLE IF NOT EXISTS node_log_chunks (
  bundle_id uuid NOT NULL REFERENCES node_log_bundles(id) ON DELETE CASCADE,
  idx int NOT NULL,
  data bytea NOT NULL,
  PRIMARY KEY (bundle_id, idx)
);
