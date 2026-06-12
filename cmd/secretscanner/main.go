package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/DevSpecOps/secretscanner/internal/metrics"
	"github.com/DevSpecOps/secretscanner/internal/revoker"
	"github.com/DevSpecOps/secretscanner/internal/rules"
	"github.com/DevSpecOps/secretscanner/internal/scanner"
)

var (
	scanPath    string
	dryRun      bool
	jsonOutput  bool
	metricsAddr string
)

func main() {
	flag.StringVar(&scanPath, "path", ".", "Directory to scan")
	flag.BoolVar(&dryRun, "dry-run", true, "Dry run mode (no actual revocation)")
	flag.BoolVar(&jsonOutput, "json", false, "Output findings as JSON")
	flag.StringVar(&metricsAddr, "metrics", ":9090", "Prometheus metrics address")
	flag.Parse()

	// Start metrics server in background
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		if err := http.ListenAndServe(metricsAddr, nil); err != nil {
			fmt.Fprintf(os.Stderr, "Metrics server error: %v\n", err)
		}
	}()

	// Initialize Rego engine
	engine, err := rules.NewRegoEngine()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load Rego policies: %v\n", err)
		os.Exit(1)
	}

	// Scan with timing
	start := time.Now()
	findings, err := scanner.Scan(scanPath, engine)
	duration := time.Since(start)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Scan error: %v\n", err)
		os.Exit(1)
	}

	// Record metrics
	metrics.ScanDuration.Observe(duration.Seconds())
	metrics.RecordFindings(findings)

	// Output
	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(findings); err != nil {
			fmt.Fprintf(os.Stderr, "JSON encode error: %v\n", err)
			os.Exit(1)
		}
	} else {
		for _, f := range findings {
			fmt.Printf("🔴 [%s] %s:%d: %s\n", f.RuleID, f.File, f.Line, truncateSecret(f.Secret))
		}
		if len(findings) == 0 {
			fmt.Println("✅ No secrets found")
		}
		fmt.Printf("📊 Scan took %.2f seconds\n", duration.Seconds())
	}

	// Revocation if not dry-run
	if !dryRun && len(findings) > 0 {
		revoker.Revoke(findings)
		os.Exit(1)
	}
}

func truncateSecret(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:6] + "..." + s[len(s)-6:]
}