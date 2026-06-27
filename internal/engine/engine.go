package engine

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/shreyshringare/Ledger/internal/metrics"
	"github.com/shreyshringare/Ledger/internal/stream"
)

type Engine struct {
	store         Store
	velocityCheck *VelocityChecker // nil = no velocity checking
	publisher     *stream.Publisher // nil = no event streaming
}

func NewEngine(s Store) *Engine {
	return &Engine{store: s}
}

func (e *Engine) Post(ctx context.Context, description string, entries []Entry) (Transaction, error) {
	txID := uuid.New()
	now := time.Now().UTC().Truncate(time.Microsecond)
	for i := range entries {
		entries[i].ID = uuid.New()
		entries[i].TransactionID = txID
		entries[i].CreatedAt = now
	}

	tx := Transaction{
		ID:          txID,
		Description: description,
		PostedAt:    now,
		Entries:     entries,
	}

	if err := tx.Validate(); err != nil {
		metrics.TransactionFailures.WithLabelValues("imbalanced").Inc()
		return Transaction{}, fmt.Errorf("validation failed: %w", err)
	}

	// Velocity check: Visa/Mastercard fraud prevention — checked before DB write
	// so a declined transaction never touches the ledger.
	if e.velocityCheck != nil {
		var totalDebit int64
		for _, entry := range entries {
			if entry.IsDebit {
				totalDebit += entry.AmountMinor
			}
		}
		if totalDebit > 0 {
			for _, entry := range entries {
				if entry.IsDebit {
					if err := e.velocityCheck.Check(ctx, entry.AccountID.String(), totalDebit); err != nil {
						metrics.TransactionFailures.WithLabelValues("velocity").Inc()
						return Transaction{}, fmt.Errorf("transaction declined: %w", err)
					}
					break
				}
			}
		}
	}

	// PostTransaction atomically fetches prev hash, computes hash, and persists.
	committed, err := e.store.PostTransaction(ctx, tx)
	if err != nil {
		metrics.TransactionFailures.WithLabelValues("db_error").Inc()
		return Transaction{}, fmt.Errorf("post transaction: %w", err)
	}

	metrics.TransactionsPosted.Inc()

	// Fire-and-forget event publish. A failure here must NEVER roll back
	// the committed transaction. The ledger's correctness does not depend
	// on the event stream being healthy.
	if e.publisher != nil {
		var totalDebit int64
		for _, entry := range committed.Entries {
			if entry.IsDebit {
				totalDebit += entry.AmountMinor
			}
		}
		go func() {
			event := stream.TransactionPostedEvent{
				EventType:   "transaction.posted",
				TxID:        committed.ID.String(),
				Description: committed.Description,
				Hash:        committed.Hash,
				PrevHash:    committed.PrevHash,
				PostedAt:    committed.PostedAt,
				EntryCount:  len(committed.Entries),
				TotalDebit:  totalDebit,
			}
			if err := e.publisher.Publish(context.Background(), committed.ID.String(), event); err != nil {
				metrics.EventPublishFailures.Inc()
			}
		}()
	}

	return committed, nil
}

func (e *Engine) Balance(ctx context.Context, accountID string, currency string) (int64, error) {
	acc, err := e.store.GetAccount(ctx, accountID)
	if err != nil {
		return 0, fmt.Errorf("get account: %w", err)
	}

	raw, err := e.store.GetBalance(ctx, accountID, currency)
	if err != nil {
		return 0, fmt.Errorf("get balance: %w", err)
	}

	return raw * int64(acc.NormalBalance()), nil
}

// WithVelocityChecker enables per-account fraud velocity checks on Post.
// Production defaults: NewVelocityChecker(5, 60, 1_000_000, 3600)
func (e *Engine) WithVelocityChecker(vc *VelocityChecker) *Engine {
	e.velocityCheck = vc
	return e
}

// WithPublisher enables fire-and-forget event streaming to Hermes on every Post.
// A nil publisher disables streaming. Publish failures never affect transaction commits.
func (e *Engine) WithPublisher(p *stream.Publisher) *Engine {
	e.publisher = p
	return e
}

func (e *Engine) Store() Store {
	return e.store
}

// ArchiveAccount soft-deletes an account by setting archived_at. Never hard-deletes.
func (e *Engine) ArchiveAccount(ctx context.Context, id string) error {
	return e.store.ArchiveAccount(ctx, id)
}

func (e *Engine) VerifyChain(ctx context.Context) error {
	timer := prometheus.NewTimer(metrics.ChainVerifyLatency)
	defer timer.ObserveDuration()

	txs, err := e.store.ListTransactions(ctx)
	if err != nil {
		return fmt.Errorf("list transactions: %w", err)
	}

	prevHash := "genesis"
	for _, tx := range txs {
		if tx.PrevHash != prevHash {
			return fmt.Errorf("chain broken at transaction %s: expected prev_hash %q, got %q",
				tx.ID, prevHash, tx.PrevHash)
		}

		expected, err := tx.ComputeHash(prevHash)
		if err != nil {
			return fmt.Errorf("compute hash for tx %s: %w", tx.ID, err)
		}

		if tx.Hash != expected {
			return fmt.Errorf("tamper detected at transaction %s: stored hash %q != computed %q",
				tx.ID, tx.Hash, expected)
		}

		prevHash = tx.Hash
	}
	return nil
}

// StartIdempotencyCleanup starts a background goroutine that deletes idempotency
// keys older than 7 days, running every hour. Stops when ctx is cancelled.
// Call this from serve.go after the engine is created.
func (e *Engine) StartIdempotencyCleanup(ctx context.Context) {
	ticker := time.NewTicker(time.Hour)
	go func() {
		for {
			select {
			case <-ticker.C:
				if err := e.store.DeleteExpiredIdempotencyKeys(ctx); err != nil {
					// Log and continue — cleanup failures are non-fatal
					_ = err
				}
			case <-ctx.Done():
				ticker.Stop()
				return
			}
		}
	}()
}
