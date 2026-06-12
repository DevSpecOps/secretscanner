package revoker

import (
	"log"

	"github.com/DevSpecOps/secretscanner/internal/scanner"
)

// Revoker interface for different services
type Revoker interface {
	Revoke(finding scanner.Finding) error
}

// AWSRevoker mocks AWS key revocation
type AWSRevoker struct{}

func (r *AWSRevoker) Revoke(finding scanner.Finding) error {
	log.Printf("[AWS] Would revoke access key: %s", finding.Secret)
	// In real implementation:
	// svc := iam.New(session.Must(session.NewSession()))
	// svc.DeleteAccessKey(&iam.DeleteAccessKeyInput{AccessKeyId: &finding.Secret, UserName: ...})
	return nil
}

// GitHubRevoker mocks GitHub token revocation
type GitHubRevoker struct{}

func (r *GitHubRevoker) Revoke(finding scanner.Finding) error {
	log.Printf("[GitHub] Would revoke token: %s", finding.Secret)
	// In real implementation:
	// curl -X DELETE -H "Authorization: token GITHUB_ADMIN_TOKEN" https://api.github.com/applications/CLIENT_ID/tokens/TOKEN
	return nil
}

// Revoke iterates over findings and revokes each using appropriate revoker
func Revoke(findings []scanner.Finding) {
	for _, f := range findings {
		var rev Revoker
		switch f.RuleID {
		case "AWS001":
			rev = &AWSRevoker{}
		case "GHPAT001":
			rev = &GitHubRevoker{}
		default:
			log.Printf("No revoker for rule %s", f.RuleID)
			continue
		}
		if err := rev.Revoke(f); err != nil {
			log.Printf("Revocation failed for %s: %v", f.RuleID, err)
		}
	}
}