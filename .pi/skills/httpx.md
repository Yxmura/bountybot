---
name: httpx
description: "HTTPx Skill — security tool usage guide for bug bounty hunting"
---

# HTTPx Skill

HTTPx is a fast HTTP probing tool by ProjectDiscovery. It checks which subdomains are alive and detects technologies.

## Installation
```bash
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

## Basic Usage
```bash
# Probe a single domain
echo example.com | httpx -silent

# Probe subdomains from file
cat subdomains.txt | httpx -silent

# Show title, status code, and technologies
cat subdomains.txt | httpx -silent -title -status-code -tech-detect

# Show web server and content length
cat subdomains.txt | httpx -silent -web-server -content-length

# JSON output for parsing
cat subdomains.txt | httpx -silent -json -o results.json

# Filter by status code
cat subdomains.txt | httpx -silent -mc 200,301,302

# Show response headers
cat subdomains.txt | httpx -silent -include-response-header
```

## HTTPx with Subfinder (one-liner)
```bash
subfinder -d example.com -silent | httpx -silent -title -status-code -tech-detect
```

## Key Options
- `-title` — Extract HTML title
- `-status-code` — Show HTTP status code
- `-tech-detect` — Detect technologies (WP, React, nginx, etc.)
- `-web-server` — Show server header
- `-json` — Output as JSON
- `-o` — Write to file
- `-mc` — Match status codes
- `-fc` — Filter status codes
