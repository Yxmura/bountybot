---
name: amass
description: "Amass Skill — security tool usage guide for bug bounty hunting"
---

# Amass Skill

OWASP Amass performs network mapping of attack surfaces and external asset discovery. Very thorough but slower — use for deep enumeration.

## Installation
```bash
go install -v github.com/owasp-amass/amass/v4/...@master
```

## Basic Usage
```bash
# Passive enumeration (no direct scanning)
amass enum -passive -d example.com

# Active enumeration (includes DNS bruteforce, zone transfers)
amass enum -active -d example.com

# Save to file
amass enum -passive -d example.com -o amass-output.txt

# Show IP addresses
amass enum -passive -d example.com -ip

# Include data sources
amass enum -passive -d example.com -src

# Multiple domains
amass enum -passive -d example.com -d example2.com
```

## Key Commands
- `amass enum` — Discover subdomains
- `amass intel` — Collect intelligence (ASNs, CIDRs, reverse whois)
- `amass track` — Track differences between enumerations
- `amass viz` — Generate visualization (D3.js force graph)

## Amass + subfinder pipeline
```bash
subfinder -d example.com -silent -o subs1.txt
amass enum -passive -d example.com -o subs2.txt
cat subs1.txt subs2.txt | sort -u > all-subs.txt
cat all-subs.txt | httpx -silent -title -status-code
```
