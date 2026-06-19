package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/shreyshringare/Ledger/internal/engine"
	"github.com/sony/gobreaker"
)

// ErrCircuitOpen is returned when the DB circuit breaker is open.
// Callers should translate this to HTTP 503 Service Unavailable.
var ErrCircuitOpen = errors.New("database circuit breaker open — retry after 30s")

// CircuitBreakerStore wraps engine.Store with PER-METHOD circuit breakers.
// Each store method gets its own gobreaker.CircuitBreaker so that a failing
// PostTransaction doesn't block healthy GetBalance calls. After 5 consecutive
// failures in a 10s window, that method's circuit opens for 30s, then one
// probe request is allowed (half-open).
type CircuitBreakerStore struct {
	wrapped  engine.Store
	breakers map[string]*gobreaker.CircuitBreaker
}

// newBreaker creates a gobreaker with standard settings for a given method name.
func newBreaker(method string) *gobreaker.CircuitBreaker {
	return gobreaker.NewCircuitBreaker(gobreaker.Settings{
		Name:        "postgres-" + method,
		MaxRequests: 1,
		Interval:    10 * time.Second,
		Timeout:     30 * time.Second,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			return counts.ConsecutiveFailures >= 5
		},
	})
}

// NewCircuitBreakerStore creates a CircuitBreakerStore wrapping the provided store.
// Initializes one breaker per store method.
func NewCircuitBreakerStore(s engine.Store) *CircuitBreakerStore {
	methods := []string{
		"CreateAccount", "GetAccount", "GetAccountByName", "ListAccounts",
		"ArchiveAccount", "PostTransaction", "GetTransaction",
		"ListTransactions", "ListTransactionsPaginated", "GetBalance",
		"CheckIdempotencyKey", "SaveIdempotencyKey", "DeleteExpiredIdempotencyKeys",
	}
	breakers := make(map[string]*gobreaker.CircuitBreaker, len(methods))
	for _, m := range methods {
		breakers[m] = newBreaker(m)
	}
	return &CircuitBreakerStore{wrapped: s, breakers: breakers}
}

// exec wraps a store call returning a value. Maps ErrOpenState → ErrCircuitOpen.
func exec[T any](cb *gobreaker.CircuitBreaker, fn func() (T, error)) (T, error) {
	result, err := cb.Execute(func() (any, error) {
		return fn()
	})
	if err != nil {
		if errors.Is(err, gobreaker.ErrOpenState) {
			var zero T
			return zero, ErrCircuitOpen
		}
		var zero T
		return zero, err
	}
	return result.(T), nil
}

// execVoid wraps a store call returning only error.
func execVoid(cb *gobreaker.CircuitBreaker, fn func() error) error {
	_, err := cb.Execute(func() (any, error) { return nil, fn() })
	if errors.Is(err, gobreaker.ErrOpenState) {
		return ErrCircuitOpen
	}
	return err
}

func (s *CircuitBreakerStore) CreateAccount(ctx context.Context, acc engine.Account) error {
	return execVoid(s.breakers["CreateAccount"], func() error { return s.wrapped.CreateAccount(ctx, acc) })
}

func (s *CircuitBreakerStore) GetAccount(ctx context.Context, id string) (engine.Account, error) {
	return exec(s.breakers["GetAccount"], func() (engine.Account, error) { return s.wrapped.GetAccount(ctx, id) })
}

func (s *CircuitBreakerStore) GetAccountByName(ctx context.Context, name string) (engine.Account, error) {
	return exec(s.breakers["GetAccountByName"], func() (engine.Account, error) { return s.wrapped.GetAccountByName(ctx, name) })
}

func (s *CircuitBreakerStore) ListAccounts(ctx context.Context) ([]engine.Account, error) {
	return exec(s.breakers["ListAccounts"], func() ([]engine.Account, error) { return s.wrapped.ListAccounts(ctx) })
}

func (s *CircuitBreakerStore) ArchiveAccount(ctx context.Context, id string) error {
	return execVoid(s.breakers["ArchiveAccount"], func() error { return s.wrapped.ArchiveAccount(ctx, id) })
}

func (s *CircuitBreakerStore) PostTransaction(ctx context.Context, tx engine.Transaction) (engine.Transaction, error) {
	return exec(s.breakers["PostTransaction"], func() (engine.Transaction, error) { return s.wrapped.PostTransaction(ctx, tx) })
}

func (s *CircuitBreakerStore) GetTransaction(ctx context.Context, id string) (engine.Transaction, error) {
	return exec(s.breakers["GetTransaction"], func() (engine.Transaction, error) { return s.wrapped.GetTransaction(ctx, id) })
}

func (s *CircuitBreakerStore) ListTransactions(ctx context.Context) ([]engine.Transaction, error) {
	return exec(s.breakers["ListTransactions"], func() ([]engine.Transaction, error) { return s.wrapped.ListTransactions(ctx) })
}

func (s *CircuitBreakerStore) ListTransactionsPaginated(ctx context.Context, limit, offset int) ([]engine.Transaction, error) {
	return exec(s.breakers["ListTransactionsPaginated"], func() ([]engine.Transaction, error) {
		return s.wrapped.ListTransactionsPaginated(ctx, limit, offset)
	})
}

func (s *CircuitBreakerStore) GetBalance(ctx context.Context, accountID string, currency string) (int64, error) {
	return exec(s.breakers["GetBalance"], func() (int64, error) { return s.wrapped.GetBalance(ctx, accountID, currency) })
}

func (s *CircuitBreakerStore) CheckIdempotencyKey(ctx context.Context, key string) ([]byte, bool, error) {
	type result struct {
		body []byte
		ok   bool
	}
	r, err := exec(s.breakers["CheckIdempotencyKey"], func() (result, error) {
		b, ok, e := s.wrapped.CheckIdempotencyKey(ctx, key)
		return result{b, ok}, e
	})
	return r.body, r.ok, err
}

func (s *CircuitBreakerStore) SaveIdempotencyKey(ctx context.Context, key string, txID uuid.UUID, responseBody []byte) error {
	return execVoid(s.breakers["SaveIdempotencyKey"], func() error { return s.wrapped.SaveIdempotencyKey(ctx, key, txID, responseBody) })
}

func (s *CircuitBreakerStore) DeleteExpiredIdempotencyKeys(ctx context.Context) error {
	return execVoid(s.breakers["DeleteExpiredIdempotencyKeys"], func() error { return s.wrapped.DeleteExpiredIdempotencyKeys(ctx) })
}

// compile-time interface check
var _ engine.Store = (*CircuitBreakerStore)(nil)
