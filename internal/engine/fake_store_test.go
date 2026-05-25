package engine

import (
	"context"
	"fmt"
)

type fakeStore struct {
	accounts     map[string]Account
	transactions []Transaction
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		accounts: make(map[string]Account),
	}
}

func (f *fakeStore) CreateAccount(_ context.Context, acc Account) error {
	f.accounts[acc.ID.String()] = acc
	return nil
}

func (f *fakeStore) GetAccount(_ context.Context, id string) (Account, error) {
	acc, ok := f.accounts[id]
	if !ok {
		return Account{}, fmt.Errorf("account %s not found", id)
	}
	return acc, nil
}

func (f *fakeStore) GetAccountByName(_ context.Context, name string) (Account, error) {
	for _, acc := range f.accounts {
		if acc.Name == name {
			return acc, nil
		}
	}
	return Account{}, fmt.Errorf("account %q not found", name)
}

func (f *fakeStore) ListAccounts(_ context.Context) ([]Account, error) {
	var out []Account
	for _, acc := range f.accounts {
		out = append(out, acc)
	}
	return out, nil
}

func (f *fakeStore) PostTransaction(_ context.Context, tx Transaction) error {
	f.transactions = append(f.transactions, tx)
	return nil
}

func (f *fakeStore) GetTransaction(_ context.Context, id string) (Transaction, error) {
	for _, tx := range f.transactions {
		if tx.ID.String() == id {
			return tx, nil
		}
	}
	return Transaction{}, fmt.Errorf("transaction %s not found", id)
}

func (f *fakeStore) ListTransactions(_ context.Context) ([]Transaction, error) {
	return f.transactions, nil
}

func (f *fakeStore) GetLastHash(_ context.Context) (string, error) {
	if len(f.transactions) == 0 {
		return "genesis", nil
	}
	return f.transactions[len(f.transactions)-1].Hash, nil
}

func (f *fakeStore) GetBalance(_ context.Context, accountID string, currency string) (int64, error) {
	var sum int64
	for _, tx := range f.transactions {
		for _, e := range tx.Entries {
			if e.AccountID.String() == accountID && e.Currency == currency {
				if e.IsDebit {
					sum += e.AmountMinor
				} else {
					sum -= e.AmountMinor
				}
			}
		}
	}
	return sum, nil
}
