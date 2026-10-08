CREATE TABLE recipients (
  alias              TEXT PRIMARY KEY,
  address            TEXT NOT NULL,
  description        TEXT NOT NULL DEFAULT '',
  pgp_public_key     TEXT,                 -- ASCII armor; NULL = no key
  require_encryption INTEGER NOT NULL DEFAULT 0,
  created_at         INTEGER NOT NULL,
  updated_at         INTEGER NOT NULL
);
