---
name: subfinder
description: "Subfinder Skill — security tool usage guide for bug bounty hunting"
---

# Subfinder Skill

Subfinder is a passive subdomain enumeration tool by ProjectDiscovery.

## Installation
```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

## Basic Usage
```bash
# Basic enumeration
subfinder -d example.com

# Silent output (only subdomains)
subfinder -d example.com -silent

# Use all available sources
subfinder -d example.com -all

# Save to file
subfinder -d example.com -o subdomains.txt

# List available sources
subfinder -ls

# Only use specific sources
subfinder -d example.com -s crtsh,dnsdumpster
```

## Recommended Workflow
1. Run with `-all` for maximum coverage
2. Deduplicate: `sort -u subdomains.txt -o subdomains.txt`
3. Pipe to httpx for probing: `cat subdomains.txt | httpx -silent`
4. Always use `-silent` when piping to other tools
