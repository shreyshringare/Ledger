CREATE TABLE entries (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    transaction_id UUID        NOT NULL REFERENCES transactions(id),
    account_id     UUID        NOT NULL REFERENCES accounts(id),
    amount_minor   BIGINT      NOT NULL CHECK (amount_minor > 0),
    currency       VARCHAR(3)  NOT NULL,
    is_debit       BOOLEAN     NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_entries_account_id ON entries(account_id);
CREATE INDEX idx_entries_transaction_id ON entries(transaction_id);