package engine

import "context"

type Store interface {
	CreateAccount(ctx context.Context, acc Account) error
	GetAccount(ctx context.Context, id string) (Account, error)
	GetAccountByName(ctx context.Context, name string) (Account, error)
	ListAccounts(ctx context.Context) ([]Account, error)

	// PostTransaction atomically fetches the last hash, computes the new hash,
	// and persists the transaction. Returns the completed transaction with Hash and PrevHash set.
	PostTransaction(ctx context.Context, tx Transaction) (Transaction, error)
	GetTransaction(ctx context.Context, id string) (Transaction, error)
	ListTransactions(ctx context.Context) ([]Transaction, error)

	GetBalance(ctx context.Context, accountID string, currency string) (int64, error)
}
