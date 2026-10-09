-- Agents and recipients live in config.yaml, which the database cannot
-- constrain: rows name agents by name (agent) and recipients by alias.

CREATE TABLE tokens (
  id            TEXT PRIMARY KEY,
  agent         TEXT NOT NULL,
  secret_hash   BLOB NOT NULL,
  label         TEXT NOT NULL DEFAULT '',
  allowed_cidrs TEXT NOT NULL DEFAULT '[]',
  created_at    INTEGER NOT NULL,
  expires_at    INTEGER,
  revoked_at    INTEGER,
  last_used_at  INTEGER,
  last_used_ip  TEXT
);
CREATE INDEX tokens_agent ON tokens(agent);

CREATE TABLE agent_keys (
  fingerprint     TEXT PRIMARY KEY,
  agent           TEXT NOT NULL,
  public_key      TEXT NOT NULL,
  private_key_enc BLOB NOT NULL,
  revocation_cert TEXT NOT NULL,             -- reason "retired": soft, past signatures stay valid
  revocation_cert_compromised TEXT NOT NULL, -- reason "compromised": hard, invalidates all signatures
  created_at      INTEGER NOT NULL,
  expires_at      INTEGER NOT NULL,
  retired_at      INTEGER
);
CREATE UNIQUE INDEX agent_keys_active ON agent_keys(agent) WHERE retired_at IS NULL;

CREATE TABLE credentials (
  id                   INTEGER PRIMARY KEY CHECK (id = 1),
  smtp_password        BLOB,               -- NULL = none; nonce||AES-256-GCM(DEK) when sealed = 1, raw bytes when 0
  smtp_password_sealed INTEGER NOT NULL DEFAULT 0,
  updated_at           INTEGER NOT NULL
);

CREATE TABLE keyring (
  id          INTEGER PRIMARY KEY CHECK (id = 1),
  dek_wrapped BLOB NOT NULL,         -- nonce||AES-256-GCM(KEK, DEK), additional data "keyring.dek"
  created_at  INTEGER NOT NULL,
  rotated_at  INTEGER                -- last re-wrap under a new KEK
);

CREATE TABLE certify_key (
  id              INTEGER PRIMARY KEY CHECK (id = 1),
  fingerprint     TEXT NOT NULL,
  public_key      TEXT NOT NULL,     -- ASCII-armored
  private_key_enc BLOB NOT NULL,     -- sealed under the DEK, passphrase removed
  created_at      INTEGER NOT NULL
);

CREATE TABLE audit (
  id               INTEGER PRIMARY KEY,
  ts               INTEGER NOT NULL,
  agent            TEXT,
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
CREATE INDEX audit_agent_ts ON audit(agent, ts);
CREATE INDEX audit_ts ON audit(ts);
