package rules

import (
	"testing"
)

func TestRegoEngine_Detect(t *testing.T) {
	engine, err := NewRegoEngine()
	if err != nil {
		t.Fatalf("Failed to create Rego engine: %v", err)
	}

	tests := []struct {
		name        string
		line        string
		wantSecret  string
		wantRuleID  string
		wantMatched bool
	}{
		{
			name:        "AWS key",
			line:        "AKIA0123456789ABCDEF",
			wantSecret:  "AKIA0123456789ABCDEF",
			wantRuleID:  "AWS001",
			wantMatched: true,
		},
		{
			name:        "RSA key",
			line:        "-----BEGIN RSA PRIVATE KEY-----",
			wantSecret:  "RSA_PRIVATE_KEY",
			wantRuleID:  "RSA001",
			wantMatched: true,
		},
		{
			name:        "GitHub PAT",
			line:        "github_pat_123ABC456DEF789GHI_JKL_123456789012",
			wantSecret:  "github_pat_123ABC456DEF789GHI_JKL_123456789012",
			wantRuleID:  "GHPAT001",
			wantMatched: true,
		},
		{
			name:        "No secret",
			line:        "Just normal text",
			wantSecret:  "",
			wantRuleID:  "",
			wantMatched: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret, ruleID, matched := engine.Detect(tt.line)
			if matched != tt.wantMatched {
				t.Errorf("matched = %v, want %v", matched, tt.wantMatched)
			}
			if secret != tt.wantSecret {
				t.Errorf("secret = %q, want %q", secret, tt.wantSecret)
			}
			if ruleID != tt.wantRuleID {
				t.Errorf("ruleID = %q, want %q", ruleID, tt.wantRuleID)
			}
		})
	}
}