package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/DevSpecOps/secretscanner/internal/scanner"
)

type regexEngine struct{}

func (r regexEngine) Detect(line string) (string, string, bool) {
	awsRe := regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	if match := awsRe.FindString(line); match != "" {
		return match, "AWS001", true
	}
	if strings.Contains(line, "BEGIN RSA PRIVATE KEY") {
		return "RSA_PRIVATE_KEY", "RSA001", true
	}
	ghRe := regexp.MustCompile(`github_pat_[A-Za-z0-9_]{22,}`)
	if match := ghRe.FindString(line); match != "" {
		return match, "GHPAT001", true
	}
	return "", "", false
}

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

	engine := &regexEngine{}
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
		fmt.Fprintln(os.Stderr, "⚠️ Revocation would happen here")
		os.Exit(1)
	}
}

func truncateSecret(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:6] + "..." + s[len(s)-6:]
}