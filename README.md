# 🔒 SecretScanner – Self-hosted secrets scanner for CI/CD

[![CI](https://github.com/DevSpecOps/secretscanner/actions/workflows/ci.yaml/badge.svg)](https://github.com/DevSpecOps/secretscanner/actions/workflows/ci.yaml)
[![Go Report Card](https://goreportcard.com/badge/github.com/DevSpecOps/secretscanner)](https://goreportcard.com/report/github.com/DevSpecOps/secretscanner)
[![GitHub release](https://img.shields.io/github/v/release/DevSpecOps/secretscanner)](https://github.com/DevSpecOps/secretscanner/releases)
[![License](https://img.shields.io/github/license/DevSpecOps/secretscanner)](LICENSE)
[![Stars](https://img.shields.io/github/stars/DevSpecOps/secretscanner?style=social)](https://github.com/DevSpecOps/secretscanner/stargazers)

> **Lightning‑fast, self‑hosted secret scanner** that detects and blocks leaked credentials before they reach production.  
> Supports AWS keys, GitHub tokens, RSA private keys – with **Open Policy Agent (Rego)** rules and **Prometheus metrics**.

## ✨ Features

- 🔍 Detects **AWS Access Keys**, **GitHub PATs**, **RSA private keys** (extensible via Rego)
- 🛡️ **Dry‑run mode** and **JSON output**
- 📊 **Prometheus metrics** (`/metrics`) for number of secrets and scan duration
- ⚡ **Blazing fast** – scans thousands of files per second
- 🔧 **CI/CD ready** – GitHub Actions, GitLab CI, pre-commit
- 🧩 **Modular design** with rule engine interface (Rego or custom)
- 🐳 **Docker** image available

## 🚀 Quick start

### Local installation

```bash
git clone https://github.com/DevSpecOps/secretscanner.git
cd secretscanner
go build -o bin/secretscanner ./cmd/secretscanner
./bin/secretscanner --path ./test/fixtures --dry-run
```

### With Docker

```bash
docker build -t secretscanner .
docker run --rm -v $(pwd):/workspace secretscanner --path /workspace --dry-run
```

### Using GitHub Action

Create `.github/workflows/secrets-scan.yml`:

```yaml
name: Scan secrets
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run SecretScanner
        uses: DevSpecOps/secretscanner@v0.1.0
        with:
          path: '.'
          dry-run: 'false'   # fails if secrets found
```

### Pre-commit hook

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: secretscanner
        name: secretscanner
        entry: secretscanner --path
        language: system
        types: [text]
        pass_filenames: false
```

## 📊 Metrics and monitoring

Run with Prometheus metrics endpoint:

```bash
./bin/secretscanner --path . --dry-run --metrics :9090
```

In another terminal:

```bash
curl http://localhost:9090/metrics
```

Example output:

```
# HELP secretscanner_secrets_found_total Total number of secrets found by rule
# TYPE secretscanner_secrets_found_total counter
secretscanner_secrets_found_total{rule_id="AWS001"} 1
secretscanner_secrets_found_total{rule_id="GHPAT001"} 1
```

## 🧪 Testing

```bash
go test ./internal/... -v
```

Coverage: ~85-90%

## 🤝 Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md). TL;DR:

```bash
make dev
```

## 📄 License

Apache 2.0 – see [LICENSE](LICENSE) file.

## 💖 Support the project

If you find SecretScanner useful, consider donating – Bitcoin and Ethereum accepted.

---

**Star** ⭐ this repo to help others discover it!