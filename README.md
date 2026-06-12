# 🔒 SecretScanner – Self-hosted secrets scanner for CI/CD

<p align="center">
  <img src="https://img.shields.io/github/go-mod/go-version/DevSpecOps/secretscanner" alt="Go version">
  <img src="https://img.shields.io/github/v/release/DevSpecOps/secretscanner" alt="GitHub release">
  <img src="https://img.shields.io/github/actions/workflow/status/DevSpecOps/secretscanner/ci.yaml?branch=main" alt="CI">
  <img src="https://goreportcard.com/badge/github.com/DevSpecOps/secretscanner" alt="Go Report Card">
  <img src="https://img.shields.io/github/license/DevSpecOps/secretscanner" alt="License Apache 2.0">
  <img src="https://img.shields.io/github/stars/DevSpecOps/secretscanner?style=social" alt="GitHub stars">
</p>

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
This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

⭐ Star this repo if you find it useful – help others discover it!
