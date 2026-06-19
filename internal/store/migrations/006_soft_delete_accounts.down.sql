DROP INDEX IF EXISTS accounts_active_idx;
ALTER TABLE accounts DROP COLUMN IF EXISTS archived_at;
