# 🔒 SecretScanner – Self-hosted secrets scanner for CI/CD

[![CI](https://github.com/DevSpecOps/secretscanner/actions/workflows/ci.yaml/badge.svg)](https://github.com/DevSpecOps/secretscanner/actions/workflows/ci.yaml)
[![Go Report Card](https://goreportcard.com/badge/github.com/DevSpecOps/secretscanner)](https://goreportcard.com/report/github.com/DevSpecOps/secretscanner)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/DevSpecOps/secretscanner/badge)](https://securityscorecards.dev/viewer/?uri=github.com/DevSpecOps/secretscanner)

> **Lightning‑fast, self‑hosted secret scanner** that detects and blocks leaked credentials before they reach production.  
> Works with GitHub Actions, GitLab CI, pre-commit, and any CI system.

## ✨ Features (Day 1 MVP)

- ✅ Detect AWS keys (`AKIA...`), GitHub personal access tokens, RSA private keys
- ✅ Dry-run mode & JSON output
- ✅ Blazing fast – regex-based with entropy plans (coming)
- ✅ Pre-commit hook support
- ✅ CI/CD ready – self-scans its own repository

## 🚀 Quick Start

### 1. Run directly from source

```bash
git clone https://github.com/DevSpecOps/secretscanner.git
cd secretscanner
make build
./bin/secretscanner --path ./ --dry-run

2. Use with pre-commit
Create .pre-commit-config.yaml:

yaml
repos:
  - repo: local
    hooks:
      - id: secretscanner
        name: secretscanner
        entry: secretscanner --path
        language: system
        types: [text]
        pass_filenames: false
3. GitHub Action example
yaml
- name: Scan for secrets
  uses: DevSpecOps/secretscanner@v0.1.0
  with:
    path: '.'
    dry-run: false   # fails if secrets found
📊 Example Output
text
🔴 [AWS001] ./test/fixtures/aws_key.txt:2: AKIA...ABCDEF
🔴 [RSA001] ./test/fixtures/rsa_key.pem:1: RSA_PRIVATE_KEY
✅ No secrets found
🧪 Testing with sample leaks
bash
mkdir -p test/fixtures
echo "AWS key: AKIA0123456789ABCDEF" > test/fixtures/aws_key.txt
echo "GitHub PAT: github_pat_123ABC456DEF" > test/fixtures/ghpat.txt
make run
📅 Roadmap
Basic regex detectors

Rego policy support (OPA)

Automatic revocation (AWS, GitHub, Slack)

Prometheus metrics & Grafana dashboard

Docker & Helm chart

GitLab CI template

🤝 Contributing
Please read CONTRIBUTING.md. To start developing:

bash
make dev
📄 License
Apache 2.0 – free for self-hosting, modification, and commercial use.

⭐ Star this repo if you find it useful – help others discover it!