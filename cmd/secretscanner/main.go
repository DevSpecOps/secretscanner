package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/DevSpecOps/secretscanner/internal/rules"
	"github.com/DevSpecOps/secretscanner/internal/scanner"
)

var (
	scanPath   string
	dryRun     bool
	jsonOutput bool
)

func main() {
	flag.StringVar(&scanPath, "path", ".", "Directory to scan")
	flag.BoolVar(&dryRun, "dry-run", true, "Dry run mode")
	flag.BoolVar(&jsonOutput, "json", false, "Output JSON")
	flag.Parse()

	// Initialize Rego engine
	engine, err := rules.NewRegoEngine()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load Rego policies: %v\n", err)
		os.Exit(1)
	}

	findings, err := scanner.Scan(scanPath, engine)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Scan error: %v\n", err)
		os.Exit(1)
	}

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(findings); err != nil {
			fmt.Fprintf(os.Stderr, "JSON error: %v\n", err)
			os.Exit(1)
		}
	} else {
		for _, f := range findings {
			fmt.Printf("🔴 [%s] %s:%d: %s\n", f.RuleID, f.File, f.Line, truncateSecret(f.Secret))
		}
		if len(findings) == 0 {
			fmt.Println("✅ No secrets found")
		}
	}

	if !dryRun && len(findings) > 0 {
		fmt.Fprintln(os.Stderr, "⚠️ Revocation would happen here (coming in Step 3)")
		os.Exit(1)
	}
}

func truncateSecret(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:6] + "..." + s[len(s)-6:]
}