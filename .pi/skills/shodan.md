---
name: shodan
description: "Shodan Skill — security tool usage guide for bug bounty hunting"
---

# Shodan Skill

Shodan CLI searches the Shodan database for internet-connected devices, services, and vulnerabilities.

## Installation
```bash
pip install shodan
shodan init YOUR_API_KEY
```

## Basic Usage
```bash
# Search for a domain
shodan domain example.com

# Search by organization
shodan search org:"Example Corp"

# Search by SSL certificate
shodan search ssl.cert.subject.cn:"example.com"

# Search for specific service
shodan search "nginx" --fields ip_str,port,org,hostnames

# Count results
shodan count "apache country:US"

# Get host information
shodan host 1.2.3.4

# Get your API info
shodan info

# Download results as JSON
shodan download results "org:Example" --limit 100
```

## Useful Search Filters
- `org:"Org Name"` — Organization
- `hostname:example.com` — Hostname
- `port:443` — Specific port
- `country:US` — Country code
- `city:"San Francisco"` — City
- `product:nginx` — Product name
- `version:1.18` — Version
- `vuln:CVE-2021-44228` — CVE
- `ssl:` — SSL related
- `http.title:"Dashboard"` — HTTP title

## Common Searches
```bash
# Find exposed databases
shodan search "product:mongodb"

# Find Jenkins instances
shodan search "x-jenkins"

# Find Elasticsearch
shodan search "product:elastic"

# Find exposed RDP
shodan search "port:3389"
```
