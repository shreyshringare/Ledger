CREATE TABLE transactions (
      id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
      description TEXT        NOT NULL,
      posted_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      hash        VARCHAR(64) NOT NULL UNIQUE,
      prev_hash   VARCHAR(64) NOT NULL
);