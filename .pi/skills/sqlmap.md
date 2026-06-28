---
name: sqlmap
description: "SQLMap Skill — security tool usage guide for bug bounty hunting"
---

# SQLMap Skill

SQLMap automates SQL injection detection and exploitation. Use carefully — it can be destructive and noisy.

## Installation
```bash
pip install sqlmap
# or
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git
```

## Basic Usage
```bash
# Test a single URL
sqlmap -u "https://example.com/page?id=1"

# Test with POST data
sqlmap -u "https://example.com/login" --data="user=admin&pass=test"

# Retrieve database banners (non-destructive)
sqlmap -u "https://example.com?id=1" --banner

# List databases
sqlmap -u "https://example.com?id=1" --dbs

# List tables in a database
sqlmap -u "https://example.com?id=1" -D dbname --tables

# Dump table contents
sqlmap -u "https://example.com?id=1" -D dbname -T users --dump

# Use request file (from Burp)
sqlmap -r request.txt

# Tamper scripts (bypass WAFs)
sqlmap -u "https://example.com?id=1" --tamper=space2comment,between,randomcase

# Batch mode (non-interactive)
sqlmap -u "https://example.com?id=1" --batch

# Risk and level (higher = more thorough but noisier)
sqlmap -u "https://example.com?id=1" --level=5 --risk=3
```

## Safety Options
```bash
# Only detect, no exploitation
sqlmap -u "https://example.com?id=1" --batch --banner

# Conservative testing
sqlmap -u "https://example.com?id=1" --level=1 --risk=1

# Test only specific parameter
sqlmap -u "https://example.com?id=1&safe=2" -p id
```

## Warning
- Never run on production without explicit authorization
- SQLMap can crash databases with heavy testing
- Always use `--batch` in automated workflows
- Start with `--level=1 --risk=1` and increase gradually
