package engine

import "context"

type Store interface {
	CreateAccount(ctx context.Context, acc Account) error
	GetAccount(ctx context.Context, id string) (Account, error)
	GetAccountByName(ctx context.Context, name string) (Account, error)
	ListAccounts(ctx context.Context) ([]Account, error)

	PostTransaction(ctx context.Context, tx Transaction) error
	GetTransaction(ctx context.Context, id string) (Transaction, error)
	ListTransactions(ctx context.Context) ([]Transaction, error)

	GetLastHash(ctx context.Context) (string, error)
	GetBalance(ctx context.Context, accountID string, currency string) (int64, error)
}
