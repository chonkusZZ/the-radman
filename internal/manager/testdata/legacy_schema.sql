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
