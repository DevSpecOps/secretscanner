```markdown
# Contributing to SecretScanner

We welcome contributions! Please follow these steps:

1. Open an issue describing your change or desired feature.
2. Run `make test` and `make lint` to ensure quality.
3. Update `README.md` if needed (new detectors, usage changes).
4. Create a Pull Request.

## Development Setup

```bash
go mod download
make build
make dev   # runs scanner on the repo itself
Adding a New Secret Detector
Edit cmd/secretscanner/main.go and add a new regex pattern inside the file walk loop. Example:

go
// Detect Slack tokens
slackRe := regexp.MustCompile(`xox[baprs]-[0-9A-Za-z\-]+`)
if match := slackRe.FindString(line); match != "" {
    findings = append(findings, Finding{...})
}
Testing
Add test files with false and true positives in test/fixtures/. The make run target will scan them.

Thank you for contributing!