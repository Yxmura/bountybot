---
name: nuclei
description: "Nuclei Skill — security tool usage guide for bug bounty hunting"
---

# Nuclei Skill

Nuclei is a template-based vulnerability scanner by ProjectDiscovery.

## Installation
```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

## Basic Usage
```bash
# Scan a single target
nuclei -target https://example.com

# Scan subdomains from file
nuclei -l subdomains.txt

# Filter by severity
nuclei -l subdomains.txt -severity critical,high

# Filter by specific template tags
nuclei -l subdomains.txt -tags xss,sqli,ssrf

# Silent output
nuclei -l subdomains.txt -silent

# Save results
nuclei -l subdomains.txt -silent -o nuclei-results.txt

# Run specific templates
nuclei -target https://example.com -t ~/nuclei-templates/http/cves/

# Update templates
nuclei -update-templates

# Show available template tags
nuclei -tl
```

## Key Options
- `-l` — Target list file
- `-target` — Single target URL
- `-severity` — Filter by severity (critical, high, medium, low, info)
- `-tags` — Filter by template tags
- `-t` — Specific template or directory
- `-silent` — Minimal output
- `-o` — Output file
- `-json` — JSON output
- `-nc` — No color (useful for piping)

## Severity Levels
- **critical** — RCE, SQLi, SSRF leading to internal access
- **high** — XSS, open redirect, auth bypass
- **medium** — Info disclosure, misconfiguration
- **low** — Best practice issues
- **info** — Informational findings
