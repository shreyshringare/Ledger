-- API keys table.
-- hashed_secret stores a bcrypt hash (cost=12) — the plaintext secret is
-- returned to the caller exactly once at creation and never stored.
-- scope is either 'read' or 'write'.
-- revoked_at NULL means the key is active.
CREATE TABLE api_keys (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    key_id        TEXT        NOT NULL UNIQUE,
    hashed_secret TEXT        NOT NULL,
    scope         TEXT        NOT NULL CHECK (scope IN ('read', 'write')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at    TIMESTAMPTZ,
    last_used_at  TIMESTAMPTZ
);

CREATE INDEX ON api_keys(key_id) WHERE revoked_at IS NULL;
