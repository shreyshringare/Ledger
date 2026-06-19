package engine

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestVelocityChecker_AllowsUnderLimit(t *testing.T) {
	vc := NewVelocityChecker(3, 60, 1_000_000, 3600)
	ctx := context.Background()
	accID := uuid.New()

	for i := 0; i < 3; i++ {
		if err := vc.Check(ctx, accID.String(), 100); err != nil {
			t.Errorf("attempt %d should be allowed, got: %v", i+1, err)
		}
	}
}

func TestVelocityChecker_BlocksFrequencyExcess(t *testing.T) {
	vc := NewVelocityChecker(2, 60, 1_000_000, 3600)
	ctx := context.Background()
	accID := uuid.New()

	vc.Check(ctx, accID.String(), 100) //nolint:errcheck
	vc.Check(ctx, accID.String(), 100) //nolint:errcheck

	if err := vc.Check(ctx, accID.String(), 100); err == nil {
		t.Error("expected frequency limit error on 3rd attempt")
	}
}

func TestVelocityChecker_BlocksAmountExcess(t *testing.T) {
	vc := NewVelocityChecker(100, 60, 500, 3600)
	ctx := context.Background()
	accID := uuid.New()

	vc.Check(ctx, accID.String(), 300) //nolint:errcheck

	if err := vc.Check(ctx, accID.String(), 300); err == nil {
		t.Error("expected amount limit error when cumulative exceeds 500")
	}
}

func TestVelocityChecker_SeparateLimitsPerAccount(t *testing.T) {
	vc := NewVelocityChecker(1, 60, 1_000_000, 3600)
	ctx := context.Background()
	a1 := uuid.New()
	a2 := uuid.New()

	vc.Check(ctx, a1.String(), 100) //nolint:errcheck
	if err := vc.Check(ctx, a1.String(), 100); err == nil {
		t.Error("expected a1 to be rate-limited")
	}
	if err := vc.Check(ctx, a2.String(), 100); err != nil {
		t.Errorf("a2 should not be limited by a1's count: %v", err)
	}
}
