#!/usr/bin/env bash
# Ledger — live interview demo
# Shows: double-entry posting, balances, SHA-256 hash chain, tamper detection
#
# Requirements:
#   - Docker running: docker compose up -d
#   - DATABASE_URL set: export DATABASE_URL="postgres://ledger:ledger@localhost:5433/ledger"
#   - Binary built:    go build -o ledger ./cmd/ledger

set -euo pipefail

LEDGER="./ledger"
DB_CONTAINER="ledger-postgres-1"
DB_USER="ledger"
DB_NAME="ledger"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

step() { echo -e "\n${CYAN}${BOLD}▶ $1${RESET}"; }
ok()   { echo -e "${GREEN}✓ $1${RESET}"; }
fail() { echo -e "${RED}✗ $1${RESET}"; }

# ── Preflight ─────────────────────────────────────────────────────────────────

step "Preflight checks"

if [ -z "${DATABASE_URL:-}" ]; then
  fail "DATABASE_URL not set. Run: export DATABASE_URL=postgres://ledger:ledger@localhost:5433/ledger"
  exit 1
fi

if ! docker inspect "$DB_CONTAINER" &>/dev/null; then
  fail "Docker container $DB_CONTAINER not running. Run: docker compose up -d"
  exit 1
fi

if [ ! -f "$LEDGER" ]; then
  echo "Building binary..."
  go build -o ledger ./cmd/ledger
fi

ok "Preflight passed"

# ── Run migrations ────────────────────────────────────────────────────────────

step "Running migrations"
$LEDGER migrate
ok "Migrations applied"

# ── Reset state ───────────────────────────────────────────────────────────────

step "Resetting database to clean state"
docker exec "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" -q \
  -c "TRUNCATE entries, transactions, accounts RESTART IDENTITY CASCADE;"
ok "Database cleared"

# ── Create accounts ───────────────────────────────────────────────────────────

step "Creating chart of accounts"
$LEDGER account create --name "Cash"             --type ASSET   --currency USD
$LEDGER account create --name "Accounts Payable" --type LIABILITY --currency USD
$LEDGER account create --name "Revenue"          --type REVENUE --currency USD
$LEDGER account create --name "Rent Expense"     --type EXPENSE --currency USD

echo ""
$LEDGER account list

# ── Post transactions ─────────────────────────────────────────────────────────

step "Posting transactions"

echo "  TX1: Customer pays \$100 (Cash ↑, Revenue ↑)"
$LEDGER post --desc "Customer payment" \
  --debit  "Cash:10000:USD" \
  --credit "Revenue:10000:USD"

echo ""
echo "  TX2: Pay rent \$40 (Rent Expense ↑, Cash ↓)"
$LEDGER post --desc "Pay rent" \
  --debit  "Rent Expense:4000:USD" \
  --credit "Cash:4000:USD"

echo ""
echo "  TX3: Another sale \$60"
$LEDGER post --desc "Second sale" \
  --debit  "Cash:6000:USD" \
  --credit "Revenue:6000:USD"

# ── Balances ──────────────────────────────────────────────────────────────────

step "Account balances"
$LEDGER balance --name "Cash"         --currency USD
echo ""
$LEDGER balance --name "Revenue"      --currency USD
echo ""
$LEDGER balance --name "Rent Expense" --currency USD

# ── Verify chain (clean) ──────────────────────────────────────────────────────

step "Verifying hash chain — should be INTACT"
$LEDGER chain verify
ok "Chain verified clean"

# ── Tamper with the database ──────────────────────────────────────────────────

step "Simulating database tampering (direct SQL UPDATE)"
echo "  Corrupting hash of transaction #1 directly in Postgres..."
docker exec "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" -q \
  -c "UPDATE transactions SET hash = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef' WHERE id = (SELECT id FROM transactions ORDER BY posted_at LIMIT 1);"
ok "Hash corrupted in DB"

# ── Verify chain (tampered) ───────────────────────────────────────────────────

step "Verifying hash chain — should DETECT TAMPERING"
if $LEDGER chain verify 2>&1; then
  fail "BUG: chain verify should have caught tampering but didn't"
  exit 1
else
  ok "Tamper detected — SHA-256 chain caught the corruption"
fi

# ── Restore clean state ───────────────────────────────────────────────────────

step "Restoring DB to clean state after tamper demo"
docker exec "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" -q \
  -c "TRUNCATE entries, transactions, accounts RESTART IDENTITY CASCADE;"
ok "DB reset — API is ready for fresh use"
echo ""

echo -e "${BOLD}Demo complete.${RESET}"
echo "The ledger posted 3 transactions, maintained correct balances,"
echo "and detected a direct database corruption via SHA-256 hash chaining."
