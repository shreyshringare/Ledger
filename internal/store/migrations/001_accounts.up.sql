 CREATE TABLE accounts (
      id         UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
      name       VARCHAR(255) NOT NULL UNIQUE,
      type       VARCHAR(20)  NOT NULL CHECK (type IN('ASSET','LIABILITY','EQUITY','REVENUE','EXPENSE')),
      currency   VARCHAR(3)   NOT NULL,
      is_active  BOOLEAN      NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
  );