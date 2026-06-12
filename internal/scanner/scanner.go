package scanner

import (
	"os"
	"path/filepath"
	"strings"
)

// Finding represents a leaked secret
type Finding struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Secret string `json:"secret"`
	RuleID string `json:"rule_id"`
}

// RuleEngine defines the interface for secret detection rules
type RuleEngine interface {
	Detect(line string) (secret string, ruleID string, matched bool)
}

// Scan walks through the given path and returns findings using the rule engine
func Scan(rootPath string, engine RuleEngine) ([]Finding, error) {
	var findings []Finding

	err := filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip unreadable
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
			secret, ruleID, matched := engine.Detect(line)
			if matched {
				findings = append(findings, Finding{
					File:   path,
					Line:   i + 1,
					Secret: secret,
					RuleID: ruleID,
				})
			}
		}
		return nil
	})
	return findings, err
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