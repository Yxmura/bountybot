---
name: gitleaks
description: "Gitleaks Skill — security tool usage guide for bug bounty hunting"
---

# Gitleaks Skill

Gitleaks scans git repositories for hardcoded secrets: API keys, passwords, tokens, and other sensitive data. Essential for finding leaked credentials in source code.

## Installation
```bash
# Download binary from GitHub releases
# https://github.com/gitleaks/gitleaks/releases
# Or:
go install github.com/gitleaks/gitleaks/v8@latest
```

## Basic Usage
```bash
# Scan a git repository
gitleaks detect --source /path/to/repo

# Scan with verbose
gitleaks detect --source . -v

# Scan uncommitted changes
gitleaks protect --staged

# Output as JSON
gitleaks detect --source . -f json -o results.json

# Output as SARIF
gitleaks detect --source . -f sarif -o results.sarif

# Use custom rules
gitleaks detect --source . -c custom-rules.toml

# No git (just scan files)
gitleaks detect --source . --no-git

# Enrich with git log
gitleaks detect --source . --log-opts="--all"
```

## What It Detects
- API keys (AWS, GCP, Azure, GitHub, GitLab, Slack, etc.)
- Private keys (RSA, SSH, PGP)
- Tokens (JWT, OAuth, PAT)
- Passwords and connection strings
- Generic high-entropy strings

## For Bug Bounty
When you find a public repo or leaked source:
```bash
# Clone and scan
git clone https://github.com/target/repo
gitleaks detect --source repo -v
```

Also look for:
- `.env` files in web root: `curl https://target.com/.env`
- `.git` directory exposure: `curl https://target.com/.git/HEAD`
- CI/CD logs: Look for build logs with environment variables
