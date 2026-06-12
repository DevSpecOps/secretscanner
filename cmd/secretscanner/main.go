package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type Finding struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Secret  string `json:"secret"`
	RuleID  string `json:"rule_id"`
}

var (
	scanPath   string
	dryRun     bool
	outputJSON bool
	verbose    bool
)

func main() {
	flag.StringVar(&scanPath, "path", ".", "Directory or file to scan")
	flag.BoolVar(&dryRun, "dry-run", true, "Report only, no revocation (default true)")
	flag.BoolVar(&outputJSON, "json", false, "Output findings as JSON")
	flag.BoolVar(&verbose, "verbose", false, "Show verbose info")
	flag.Parse()

	findings := []Finding{}

	err := filepath.Walk(scanPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if verbose {
				fmt.Fprintf(os.Stderr, "skip %s: %v\n", path, err)
			}
			return nil
		}
		if info.IsDir() {
			name := info.Name()
			if name == ".git" || name == "vendor" || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if isBinary(path) {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		lines := strings.Split(string(content), "\n")
		for i, line := range lines {
			// AWS keys
			awsRe := regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
			if match := awsRe.FindString(line); match != "" {
				findings = append(findings, Finding{
					File:    path,
					Line:    i + 1,
					Secret:  match,
					RuleID:  "AWS001",
				})
			}
			// RSA private key
			if strings.Contains(line, "BEGIN RSA PRIVATE KEY") {
				findings = append(findings, Finding{
					File:    path,
					Line:    i + 1,
					Secret:  "RSA_PRIVATE_KEY",
					RuleID:  "RSA001",
				})
			}
			// GitHub tokens
			ghRe := regexp.MustCompile(`github_pat_[A-Za-z0-9_]{22,}`)
			if match := ghRe.FindString(line); match != "" {
				findings = append(findings, Finding{
					File:    path,
					Line:    i + 1,
					Secret:  match,
					RuleID:  "GHPAT001",
				})
			}
		}
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Scan error: %v\n", err)
		os.Exit(1)
	}

	if outputJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(findings)
	} else {
		for _, f := range findings {
			fmt.Printf("🔴 [%s] %s:%d: %s\n", f.RuleID, f.File, f.Line, truncateSecret(f.Secret))
		}
		if len(findings) == 0 {
			fmt.Println("✅ No secrets found")
		}
	}

	if !dryRun && len(findings) > 0 {
		fmt.Fprintln(os.Stderr, "⚠️  Revocation not yet fully implemented, but would block commit.")
		os.Exit(1)
	}
	os.Exit(0)
}

func isBinary(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, 512)
	n, _ := f.Read(buf)
	for i := 0; i < n; i++ {
		if buf[i] == 0 {
			return true
		}
	}
	return false
}

func truncateSecret(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:6] + "..." + s[len(s)-6:]
}