package stream

import "time"

// TransactionPostedEvent is the wire schema published to Hermes on every
// successful Post(). Downstream consumers depend on this schema remaining
// backward-compatible — new fields are additive only.
type TransactionPostedEvent struct {
	EventType   string    `json:"event_type"` // always "transaction.posted"
	TxID        string    `json:"tx_id"`
	Description string    `json:"description"`
	Hash        string    `json:"hash"`
	PrevHash    string    `json:"prev_hash"`
	PostedAt    time.Time `json:"posted_at"`
	EntryCount  int       `json:"entry_count"`
	TotalDebit  int64     `json:"total_debit_minor"`
	Currency    string    `json:"currency"`
}

// FraudRingDetectedEvent is published when Tarjan's SCC detects a cycle.
type FraudRingDetectedEvent struct {
	EventType      string    `json:"event_type"` // always "fraud.ring_detected"
	Accounts       []string  `json:"accounts"`
	CycleLength    int       `json:"cycle_length"`
	TotalFlow      int64     `json:"total_flow_minor"`
	SuspicionScore float64   `json:"suspicion_score"`
	DetectedAt     time.Time `json:"detected_at"`
}
