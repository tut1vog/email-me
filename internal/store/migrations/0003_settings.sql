CREATE TABLE settings (
  id                   INTEGER PRIMARY KEY CHECK (id = 1),
  doc                  TEXT NOT NULL,        -- JSON config.Settings, normalized (defaults applied)
  smtp_password        BLOB,                 -- NULL = none; nonce||AES-256-GCM(DEK) when sealed = 1, raw bytes when 0
  smtp_password_sealed INTEGER NOT NULL DEFAULT 0,
  updated_at           INTEGER NOT NULL
);
