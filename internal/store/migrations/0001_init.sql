CREATE TABLE agents (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL DEFAULT '',
  enabled     INTEGER NOT NULL DEFAULT 1,
  policy      TEXT NOT NULL DEFAULT '{}',
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL
);

CREATE TABLE tokens (
  id            TEXT PRIMARY KEY,
  agent_id      TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  secret_hash   BLOB NOT NULL,
  label         TEXT NOT NULL DEFAULT '',
  allowed_cidrs TEXT NOT NULL DEFAULT '[]',
  created_at    INTEGER NOT NULL,
  expires_at    INTEGER,
  revoked_at    INTEGER,
  last_used_at  INTEGER,
  last_used_ip  TEXT
);
CREATE INDEX tokens_agent ON tokens(agent_id);

CREATE TABLE agent_keys (
  fingerprint     TEXT PRIMARY KEY,
  agent_id        TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  public_key      TEXT NOT NULL,
  private_key_enc BLOB NOT NULL,
  revocation_cert TEXT NOT NULL,             -- reason "retired": soft, past signatures stay valid
  revocation_cert_compromised TEXT NOT NULL, -- reason "compromised": hard, invalidates all signatures
  created_at      INTEGER NOT NULL,
  expires_at      INTEGER NOT NULL,
  retired_at      INTEGER
);
CREATE UNIQUE INDEX agent_keys_active ON agent_keys(agent_id) WHERE retired_at IS NULL;

CREATE TABLE audit (
  id               INTEGER PRIMARY KEY,
  ts               INTEGER NOT NULL,
  agent_id         TEXT,
  token_id         TEXT,
  source_ip        TEXT,
  recipients       TEXT,
  size_bytes       INTEGER,
  attachment_count INTEGER,
  services         TEXT,
  encrypted        INTEGER,
  signed           INTEGER,
  signing_key_fpr  TEXT,
  transport        TEXT,
  status           TEXT NOT NULL,
  error_code       TEXT,
  upstream_code    INTEGER,
  message_id       TEXT,
  subject          TEXT
);
CREATE INDEX audit_agent_ts ON audit(agent_id, ts);
CREATE INDEX audit_ts ON audit(ts);
