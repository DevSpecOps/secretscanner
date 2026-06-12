package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/DevSpecOps/secretscanner/internal/scanner"
)

var (
	// SecretsFound counts secrets by rule ID
	SecretsFound = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "secretscanner_secrets_found_total",
			Help: "Total number of secrets found by rule",
		},
		[]string{"rule_id"},
	)

	// ScanDuration measures scan time in seconds
	ScanDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "secretscanner_scan_duration_seconds",
			Help:    "Duration of scan in seconds",
			Buckets: prometheus.DefBuckets,
		},
	)
)

// RecordFindings updates metrics for each finding
func RecordFindings(findings []scanner.Finding) {
	for _, f := range findings {
		SecretsFound.WithLabelValues(f.RuleID).Inc()
	}
}