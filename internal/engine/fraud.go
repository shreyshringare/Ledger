package engine

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// VelocityChecker enforces per-account transaction frequency and amount limits.
// This mirrors Visa's Real-Time Fraud Scoring velocity checks applied before
// authorization. Two limits are enforced independently:
//   - Frequency: max N transactions per frequencyWindowSec
//   - Amount:    max M minor units cumulative per amountWindowSec
//
// Both windows are sliding (not fixed) to prevent boundary exploitation.
type VelocityChecker struct {
	mu              sync.Mutex
	windows         map[string]*accountVelocity
	freqLimit       int
	freqWindowSec   int
	amountLimit     int64
	amountWindowSec int
}

type accountVelocity struct {
	mu      sync.Mutex
	txTimes []time.Time   // timestamps for frequency window
	amounts []amountEntry // (time, amount) for amount window
}

type amountEntry struct {
	ts     time.Time
	amount int64
}

// NewVelocityChecker creates a VelocityChecker.
// freqLimit: max transactions per freqWindowSec.
// amountLimit: max cumulative minor units per amountWindowSec.
// Production defaults: NewVelocityChecker(5, 60, 1_000_000, 3600)
// — 5 txn/min, $10,000/hour (in minor units of USD).
func NewVelocityChecker(freqLimit, freqWindowSec int, amountLimit int64, amountWindowSec int) *VelocityChecker {
	return &VelocityChecker{
		windows:         make(map[string]*accountVelocity),
		freqLimit:       freqLimit,
		freqWindowSec:   freqWindowSec,
		amountLimit:     amountLimit,
		amountWindowSec: amountWindowSec,
	}
}

// Check validates the transaction against velocity limits for the given account.
// Returns an error if either limit is exceeded; nil if the transaction is allowed.
// On success, the transaction is recorded in the sliding windows.
func (vc *VelocityChecker) Check(_ context.Context, accountID string, amountMinor int64) error {
	vc.mu.Lock()
	av, ok := vc.windows[accountID]
	if !ok {
		av = &accountVelocity{}
		vc.windows[accountID] = av
	}
	vc.mu.Unlock()

	av.mu.Lock()
	defer av.mu.Unlock()

	now := time.Now()

	// Evict stale frequency entries
	freqCutoff := now.Add(-time.Duration(vc.freqWindowSec) * time.Second)
	i := 0
	for i < len(av.txTimes) && av.txTimes[i].Before(freqCutoff) {
		i++
	}
	av.txTimes = av.txTimes[i:]

	if len(av.txTimes) >= vc.freqLimit {
		return fmt.Errorf("velocity limit: max %d transactions per %ds exceeded — possible fraud detected",
			vc.freqLimit, vc.freqWindowSec)
	}

	// Evict stale amount entries
	amtCutoff := now.Add(-time.Duration(vc.amountWindowSec) * time.Second)
	j := 0
	for j < len(av.amounts) && av.amounts[j].ts.Before(amtCutoff) {
		j++
	}
	av.amounts = av.amounts[j:]

	var cumulative int64
	for _, e := range av.amounts {
		cumulative += e.amount
	}
	if cumulative+amountMinor > vc.amountLimit {
		return fmt.Errorf("velocity limit: cumulative amount %d exceeds %d per %ds — possible fraud detected",
			cumulative+amountMinor, vc.amountLimit, vc.amountWindowSec)
	}

	// Record this transaction
	av.txTimes = append(av.txTimes, now)
	av.amounts = append(av.amounts, amountEntry{ts: now, amount: amountMinor})
	return nil
}
