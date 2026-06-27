package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
    TransactionsPosted = prometheus.NewCounter(prometheus.CounterOpts{
        Name: "ledger_transactions_posted_total",
        Help: "Total number of transactions successfully posted",
    })

    TransactionFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
        Name: "ledger_transaction_failures_total",
        Help: "Transaction failures by reason",
    }, []string{"reason"}) // "imbalanced", "db_error", "currency_mismatch", "velocity"

    ChainVerifyLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
        Name:    "ledger_chain_verify_seconds",
        Help:    "Time taken to verify the full SHA-256 chain",
        Buckets: prometheus.ExponentialBuckets(0.001, 2, 15),
    })

    FraudRingsDetected = prometheus.NewGauge(prometheus.GaugeOpts{
        Name: "ledger_fraud_rings_active",
        Help: "Number of fraud rings detected in the most recent scan",
    })

    EventPublishFailures = prometheus.NewCounter(prometheus.CounterOpts{
        Name: "ledger_stream_publish_failures_total",
        Help: "Failed publishes to Hermes (does not affect transaction commit)",
    })
)

func init() {
    prometheus.MustRegister(
        TransactionsPosted,
        TransactionFailures,
        ChainVerifyLatency,
        FraudRingsDetected,
        EventPublishFailures,
    )
}
