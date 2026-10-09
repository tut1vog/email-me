CREATE TABLE keyring (
  id          INTEGER PRIMARY KEY CHECK (id = 1),
  dek_wrapped BLOB NOT NULL,         -- nonce||AES-256-GCM(KEK, DEK), additional data "keyring.dek"
  created_at  INTEGER NOT NULL,
  rotated_at  INTEGER                -- last re-wrap under a new KEK
);

CREATE TABLE admin (
  id            INTEGER PRIMARY KEY CHECK (id = 1),
  password_hash TEXT NOT NULL,       -- argon2id PHC string
  must_change   INTEGER NOT NULL,    -- 1 = a setup password: the next login must replace it
  updated_at    INTEGER NOT NULL
);

CREATE TABLE certify_key (
  id              INTEGER PRIMARY KEY CHECK (id = 1),
  fingerprint     TEXT NOT NULL,
  public_key      TEXT NOT NULL,     -- ASCII-armored
  private_key_enc BLOB NOT NULL,     -- sealed under the DEK, passphrase removed
  created_at      INTEGER NOT NULL
);
