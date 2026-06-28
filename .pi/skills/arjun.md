---
name: arjun
description: "Arjun Skill — security tool usage guide for bug bounty hunting"
---

# Arjun Skill

Arjun discovers hidden HTTP parameters. Works by fuzzing parameter names and analyzing response differences.

## Installation
```bash
pip install arjun
```

## Basic Usage
```bash
# Scan single URL
arjun -u https://example.com/endpoint

# Scan with parameters
arjun -u https://example.com/page?existing=1

# POST request
arjun -u https://example.com/api -m POST

# Include JSON body
arjun -u https://example.com/api -m JSON

# Multiple URLs
arjun -i urls.txt

# Custom wordlist
arjun -u https://example.com/page -w /path/to/params.txt

# Stable output
arjun -u https://example.com/page --stable

# Specify concurrent requests
arjun -u https://example.com/page -t 20
```

## Common Workflow
```bash
# Find endpoints, discover parameters, test them
katana -u https://example.com -silent | arjun -i /dev/stdin --stable
```

## Discovered Parameters → Next Steps
- `id`, `user`, `uid` → IDOR testing
- `redirect`, `url`, `next` → Open redirect
- `file`, `template`, `page` → LFI/SSTI
- `q`, `search`, `query` → XSS/SQLi
- `token`, `auth` → Auth bypass
- `callback`, `webhook`, `ping` → SSRF
