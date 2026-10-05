-- Programmatic API access: hashed bearer tokens the user creates from their
-- account, e.g. for the nmap plugin uploading scans. Only the SHA-256 of the
-- token is stored; the raw key is shown once at creation.
CREATE TABLE api_tokens (
  id TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  created_at TEXT NOT NULL,
  last_used_at TEXT
);
CREATE INDEX idx_api_tokens_user ON api_tokens (user_id);
