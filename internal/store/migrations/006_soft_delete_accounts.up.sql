ALTER TABLE accounts ADD COLUMN archived_at TIMESTAMPTZ;

-- Partial index: only index active accounts for list queries
CREATE INDEX accounts_active_idx ON accounts (created_at) WHERE archived_at IS NULL;
