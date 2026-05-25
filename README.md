# Ledger

A double-entry accounting engine with SHA-256 hash chaining, written in Go.

Every transaction is cryptographically linked to the previous one. A direct database edit — bypassing the application entirely — is detectable in O(n) time by recomputing the chain.

---

## Architecture

```
cmd/ledger/        CLI + HTTP server (cobra)
internal/engine/   Core domain: double-entry logic, hash chain, validation
internal/store/    PostgreSQL implementation of the Store interface
internal/api/      HTTP handlers (chi router)
```

### Key decisions

**`Store` interface lives in `engine`, not `store`**
The consumer owns the contract. This means `engine` has zero knowledge of Postgres — it depends only on the interface it defines. The import graph flows one way: `cmd → engine ← store`, never `engine → store`.

**`int64` minor units everywhere**
All amounts are stored as integer cents (USD 1.00 = 100). IEEE 754 floating point is non-associative: `0.1 + 0.2 ≠ 0.3`. Financial software that uses `float64` has a latent correctness bug.

**SHA-256 hash chain**
Each transaction stores `prev_hash` (the hash of the preceding transaction) and `hash` (SHA-256 of its own ID, description, timestamp, prev_hash, and entries). The genesis transaction uses `"genesis"` as its prev_hash.

```
genesis → tx1.hash → tx2.prev_hash == tx1.hash → tx3.prev_hash == tx2.hash
```

If anyone runs `UPDATE transactions SET amount = ... WHERE id = ...` directly in Postgres, `ledger chain verify` recomputes every hash from scratch and finds the mismatch.

**SERIALIZABLE isolation on PostTransaction**
`GetLastHash` and `INSERT` happen inside a single SERIALIZABLE database transaction. Two concurrent posts cannot silently interleave — one will retry. This closes the race condition where two requests both read the same `prev_hash` and produce a broken chain.

**No ORM**
Raw `pgx/v5` queries. SQL is explicit, type-safe at the scan level, and readable in code review.

---

## Quick start

**Requirements:** Go 1.21+, Docker

```bash
# Start Postgres
docker compose up -d

# Set connection string
export DATABASE_URL="postgres://ledger:ledger@localhost:5433/ledger"

# Run migrations
go run ./cmd/ledger migrate

# Start HTTP server
go run ./cmd/ledger serve
# Ledger API listening on :8080
```

---

## REST API

### Accounts

```bash
# Create account
curl -X POST http://localhost:8080/accounts \
  -H "Content-Type: application/json" \
  -d '{"name":"Cash","type":"ASSET","currency":"USD"}'

# List accounts
curl http://localhost:8080/accounts

# Account balance
curl "http://localhost:8080/accounts/{id}/balance?currency=USD"
```

Account types: `ASSET`, `LIABILITY`, `EQUITY`, `REVENUE`, `EXPENSE`

### Transactions

```bash
# Post a double-entry transaction
curl -X POST http://localhost:8080/transactions \
  -H "Content-Type: application/json" \
  -d '{
    "description": "Customer payment",
    "entries": [
      {"account_name": "Cash",    "amount": 10000, "currency": "USD", "is_debit": true},
      {"account_name": "Revenue", "amount": 10000, "currency": "USD", "is_debit": false}
    ]
  }'

# Get transaction
curl http://localhost:8080/transactions/{id}
```

Amounts are in minor units (cents). `10000` = USD 100.00.

The engine enforces the double-entry invariant at the domain layer: if debits ≠ credits, the transaction is rejected before any database write.

### Hash chain

```bash
curl http://localhost:8080/chain/verify
# {"intact": true,  "message": "chain intact — no tampering detected"}
# {"intact": false, "message": "tamper detected at transaction abc123: ..."}
```

---

## CLI

The same engine is also accessible as a CLI (useful for scripting and demos):

```bash
go build -o ledger ./cmd/ledger

./ledger migrate
./ledger account create --name "Cash" --type ASSET --currency USD
./ledger account list
./ledger post --desc "Sale" --debit "Cash:10000:USD" --credit "Revenue:10000:USD"
./ledger balance --name "Cash" --currency USD
./ledger chain verify
```

---

## Demo

Runs a full end-to-end scenario: create accounts, post transactions, verify the chain, simulate a direct database corruption, and verify detection:

```bash
./demo.sh
```

---

## Tests

Unit tests use a `FakeStore` injected via the `Store` interface — no Postgres required:

```bash
go test ./...
```

The fake store mirrors the real store's hash-chain logic, so tests cover the full domain invariants: double-entry validation, chain construction, tamper detection, and normal-balance accounting.

---

## Balance semantics

Balances apply the accounting normal balance convention:

| Type | Normal balance | Increases with |
|------|---------------|----------------|
| ASSET | Debit | Debit entries |
| EXPENSE | Debit | Debit entries |
| LIABILITY | Credit | Credit entries |
| EQUITY | Credit | Credit entries |
| REVENUE | Credit | Credit entries |

`GET /accounts/{id}/balance` returns the natural balance — a Revenue account with $160 in credit entries returns `16000`, not `-16000`.
