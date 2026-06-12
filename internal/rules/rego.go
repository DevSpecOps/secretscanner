package rules

import (
	"context"
	"embed"
	"fmt"
	"regexp"

	"github.com/open-policy-agent/opa/rego"
)

//go:embed rules.rego
var policyFile embed.FS

type RegoEngine struct {
	preparedEval rego.PreparedEvalQuery
}

func NewRegoEngine() (*RegoEngine, error) {
	policyContent, err := policyFile.ReadFile("rules.rego")
	if err != nil {
		return nil, fmt.Errorf("failed to read policy: %w", err)
	}
	query := "data.secretscanner.detect"
	r := rego.New(
		rego.Query(query),
		rego.Module("rules.rego", string(policyContent)),
	)
	ctx := context.Background()
	prepared, err := r.PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare rego: %w", err)
	}
	return &RegoEngine{preparedEval: prepared}, nil
}

func (r *RegoEngine) Detect(line string) (secret string, ruleID string, matched bool) {
	ctx := context.Background()
	input := map[string]interface{}{"line": line}
	results, err := r.preparedEval.Eval(ctx, rego.EvalInput(input))
	if err != nil || len(results) == 0 || len(results[0].Expressions) == 0 {
		return "", "", false
	}
	resultVal := results[0].Expressions[0].Value
	resultMap, ok := resultVal.(map[string]interface{})
	if !ok {
		return "", "", false
	}
	matchedVal, ok := resultMap["matched"].(bool)
	if !ok || !matchedVal {
		return "", "", false
	}
	ruleID, _ = resultMap["rule_id"].(string)
	// Extract secret using Go regex based on ruleID
	switch ruleID {
	case "AWS001":
		re := regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
		if match := re.FindString(line); match != "" {
			secret = match
		}
	case "GHPAT001":
		re := regexp.MustCompile(`github_pat_[A-Za-z0-9_]{22,}`)
		if match := re.FindString(line); match != "" {
			secret = match
		}
	case "RSA001":
		if contains(line, "BEGIN RSA PRIVATE KEY") {
			secret = "RSA_PRIVATE_KEY"
		}
	default:
		secret = ""
	}
	return secret, ruleID, matchedVal
}

// Helper because we don't have strings import yet
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || indexOf(s, substr) != -1))
}
func indexOf(s, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}