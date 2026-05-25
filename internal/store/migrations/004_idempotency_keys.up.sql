CREATE TABLE idempotency_keys (
    key            TEXT PRIMARY KEY,
    transaction_id UUID        NOT NULL REFERENCES transactions(id),
    response_body  JSONB       NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX ON idempotency_keys (created_at);
