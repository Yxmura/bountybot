---
name: wafw00f
description: "Wafw00f Skill — security tool usage guide for bug bounty hunting"
---

# Wafw00f Skill

Wafw00f detects and identifies Web Application Firewalls (WAFs) protecting a target. Essential for understanding what defenses you're up against.

## Installation
```bash
pip install wafw00f
```

## Basic Usage
```bash
# Single target
wafw00f https://example.com

# Multiple targets from file
wafw00f -i targets.txt

# Verbose mode
wafw00f https://example.com -v

# Output as JSON
wafw00f https://example.com -o json

# Test all WAFs (slower but thorough)
wafw00f https://example.com -a

# Proxy support
wafw00f https://example.com -p http://127.0.0.1:8080
```

## What It Detects
- Cloudflare, Akamai, CloudFront (CDN/WAF)
- ModSecurity, NAXSI (OSS WAFs)
- Imperva, F5, Fortinet, Barracuda (Enterprise)
- AWS WAF, Azure WAF, GCP Cloud Armor
- Sucuri, Wordfence (CMS WAFs)
- 50+ WAF signatures

## After Detection
- If Cloudflare → Try origin IP discovery: `shodan host example.com`
- If ModSecurity → Test CRS bypass payloads
- If no WAF → More aggressive testing is feasible
