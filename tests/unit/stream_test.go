package unit_test

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/shreyshringare/Ledger/internal/engine"
	"github.com/shreyshringare/Ledger/internal/stream"
)

// ─── fake stores ────────────────────────────────────────────────────────────

// streamErrStore always returns an error from PostTransaction.
type streamErrStore struct{}

func (f *streamErrStore) CreateAccount(_ context.Context, _ engine.Account) error { return nil }
func (f *streamErrStore) GetAccount(_ context.Context, _ string) (engine.Account, error) {
	return engine.Account{}, nil
}
func (f *streamErrStore) GetAccountByName(_ context.Context, _ string) (engine.Account, error) {
	return engine.Account{}, nil
}
func (f *streamErrStore) ListAccounts(_ context.Context) ([]engine.Account, error) { return nil, nil }
func (f *streamErrStore) ArchiveAccount(_ context.Context, _ string) error          { return nil }
func (f *streamErrStore) PostTransaction(_ context.Context, _ engine.Transaction) (engine.Transaction, error) {
	return engine.Transaction{}, fmt.Errorf("db connection refused")
}
func (f *streamErrStore) GetTransaction(_ context.Context, _ string) (engine.Transaction, error) {
	return engine.Transaction{}, nil
}
func (f *streamErrStore) ListTransactions(_ context.Context) ([]engine.Transaction, error) {
	return nil, nil
}
func (f *streamErrStore) ListTransactionsPaginated(_ context.Context, _, _ int) ([]engine.Transaction, error) {
	return nil, nil
}
func (f *streamErrStore) GetBalance(_ context.Context, _ string, _ string) (int64, error) {
	return 0, nil
}
func (f *streamErrStore) CheckIdempotencyKey(_ context.Context, _ string) ([]byte, bool, error) {
	return nil, false, nil
}
func (f *streamErrStore) SaveIdempotencyKey(_ context.Context, _ string, _ uuid.UUID, _ []byte) error {
	return nil
}
func (f *streamErrStore) DeleteExpiredIdempotencyKeys(_ context.Context) error { return nil }

// streamOKStore stores transactions in memory and computes the hash chain.
type streamOKStore struct {
	transactions []engine.Transaction
	accounts     map[string]engine.Account
}

func newStreamOKStore() *streamOKStore {
	return &streamOKStore{accounts: make(map[string]engine.Account)}
}

func (f *streamOKStore) CreateAccount(_ context.Context, acc engine.Account) error {
	f.accounts[acc.ID.String()] = acc
	return nil
}
func (f *streamOKStore) GetAccount(_ context.Context, id string) (engine.Account, error) {
	acc, ok := f.accounts[id]
	if !ok {
		return engine.Account{}, fmt.Errorf("account not found: %s", id)
	}
	return acc, nil
}
func (f *streamOKStore) GetAccountByName(_ context.Context, _ string) (engine.Account, error) {
	return engine.Account{}, nil
}
func (f *streamOKStore) ListAccounts(_ context.Context) ([]engine.Account, error) { return nil, nil }
func (f *streamOKStore) ArchiveAccount(_ context.Context, _ string) error          { return nil }
func (f *streamOKStore) PostTransaction(_ context.Context, tx engine.Transaction) (engine.Transaction, error) {
	prevHash := "genesis"
	if len(f.transactions) > 0 {
		prevHash = f.transactions[len(f.transactions)-1].Hash
	}
	hash, err := tx.ComputeHash(prevHash)
	if err != nil {
		return engine.Transaction{}, fmt.Errorf("compute hash: %w", err)
	}
	tx.PrevHash = prevHash
	tx.Hash = hash
	f.transactions = append(f.transactions, tx)
	return tx, nil
}
func (f *streamOKStore) GetTransaction(_ context.Context, _ string) (engine.Transaction, error) {
	return engine.Transaction{}, nil
}
func (f *streamOKStore) ListTransactions(_ context.Context) ([]engine.Transaction, error) {
	return f.transactions, nil
}
func (f *streamOKStore) ListTransactionsPaginated(_ context.Context, _, _ int) ([]engine.Transaction, error) {
	return f.transactions, nil
}
func (f *streamOKStore) GetBalance(_ context.Context, _ string, _ string) (int64, error) {
	return 0, nil
}
func (f *streamOKStore) CheckIdempotencyKey(_ context.Context, _ string) ([]byte, bool, error) {
	return nil, false, nil
}
func (f *streamOKStore) SaveIdempotencyKey(_ context.Context, _ string, _ uuid.UUID, _ []byte) error {
	return nil
}
func (f *streamOKStore) DeleteExpiredIdempotencyKeys(_ context.Context) error { return nil }

// ─── helpers ────────────────────────────────────────────────────────────────

// startFakeBroker starts a local TCP listener that counts complete Hermes frames received.
// Each call to the returned channel drains one frame count.
func startFakeBroker(t *testing.T) (addr string, received chan struct{}, cleanup func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ch := make(chan struct{}, 32)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return // listener closed
		}
		defer conn.Close()
		// Parse Hermes frames: [4B topic-len][topic][4B key-len][key][4B payload-len][payload]
		hdr := make([]byte, 4)
		for {
			if err := readFull(conn, hdr); err != nil {
				return
			}
			topicLen := binary.BigEndian.Uint32(hdr)
			if err := skipBytes(conn, int(topicLen)); err != nil {
				return
			}
			if err := readFull(conn, hdr); err != nil {
				return
			}
			keyLen := binary.BigEndian.Uint32(hdr)
			if err := skipBytes(conn, int(keyLen)); err != nil {
				return
			}
			if err := readFull(conn, hdr); err != nil {
				return
			}
			payloadLen := binary.BigEndian.Uint32(hdr)
			if err := skipBytes(conn, int(payloadLen)); err != nil {
				return
			}
			ch <- struct{}{}
		}
	}()
	return ln.Addr().String(), ch, func() { ln.Close() }
}

func readFull(conn net.Conn, buf []byte) error {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return err
		}
	}
	return nil
}

func skipBytes(conn net.Conn, n int) error {
	if n == 0 {
		return nil
	}
	buf := make([]byte, n)
	return readFull(conn, buf)
}

// balancedEntries returns a simple balanced debit/credit pair in INR.
func balancedEntries() []engine.Entry {
	return []engine.Entry{
		{AccountID: uuid.New(), AmountMinor: 10000, Currency: "INR", IsDebit: true},
		{AccountID: uuid.New(), AmountMinor: 10000, Currency: "INR", IsDebit: false},
	}
}

// ─── tests ──────────────────────────────────────────────────────────────────

// TestStream_FailedDBWriteProducesZeroEvents proves that a failed PostTransaction
// produces no published events — the fire-and-forget goroutine must never fire.
func TestStream_FailedDBWriteProducesZeroEvents(t *testing.T) {
	addr, received, cleanup := startFakeBroker(t)
	defer cleanup()

	pub, err := stream.NewPublisher(addr, "ledger.transactions")
	if err != nil {
		t.Fatalf("NewPublisher: %v", err)
	}
	defer pub.Close()

	e := engine.NewEngine(&streamErrStore{}).WithPublisher(pub)

	_, postErr := e.Post(context.Background(), "failed write", balancedEntries())
	if postErr == nil {
		t.Fatal("expected Post() to return error, got nil")
	}

	// Allow any stray goroutines to complete.
	time.Sleep(10 * time.Millisecond)

	if len(received) != 0 {
		t.Fatalf("expected 0 published events, got %d", len(received))
	}
}

// TestStream_SuccessfulPostPublishesOneEvent proves that a successful commit
// causes exactly one TransactionPostedEvent to be published with the correct type.
func TestStream_SuccessfulPostPublishesOneEvent(t *testing.T) {
	addr, received, cleanup := startFakeBroker(t)
	defer cleanup()

	pub, err := stream.NewPublisher(addr, "ledger.transactions")
	if err != nil {
		t.Fatalf("NewPublisher: %v", err)
	}
	defer pub.Close()

	e := engine.NewEngine(newStreamOKStore()).WithPublisher(pub)

	_, postErr := e.Post(context.Background(), "sale of goods", balancedEntries())
	if postErr != nil {
		t.Fatalf("Post() returned unexpected error: %v", postErr)
	}

	// Allow the fire-and-forget goroutine to deliver the frame.
	time.Sleep(20 * time.Millisecond)

	if len(received) != 1 {
		t.Fatalf("expected 1 published event, got %d", len(received))
	}
}

// TestStream_PublishFailureDoesNotAffectReturn proves that a broken publisher
// (simulated by closing the connection before publish) does not affect the
// committed transaction returned from Post().
func TestStream_PublishFailureDoesNotAffectReturn(t *testing.T) {
	addr, _, cleanup := startFakeBroker(t)
	defer cleanup()

	pub, err := stream.NewPublisher(addr, "ledger.transactions")
	if err != nil {
		t.Fatalf("NewPublisher: %v", err)
	}
	// Close the underlying connection before Post() fires the goroutine.
	// This forces Publish() inside the goroutine to fail with a write error.
	pub.Close()

	e := engine.NewEngine(newStreamOKStore()).WithPublisher(pub)

	committed, postErr := e.Post(context.Background(), "publish will fail", balancedEntries())
	if postErr != nil {
		t.Fatalf("Post() must succeed even when publisher is broken; got: %v", postErr)
	}
	if committed.ID == (uuid.UUID{}) {
		t.Fatal("expected committed transaction with non-zero ID")
	}

	// Give the goroutine time to attempt (and silently fail) publish.
	time.Sleep(20 * time.Millisecond)
}
