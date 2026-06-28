---
name: gau
description: "Gau (Get All URLs) — URL discovery from passive sources for bug bounty hunting"
---

# Gau Skill (Get All URLs)

Gau fetches known URLs from AlienVault's Open Threat Exchange, the Wayback Machine, and Common Crawl. Essential for discovering endpoints and parameters.

## Installation
```bash
go install github.com/lc/gau/v2/cmd/gau@latest
```

## Basic Usage
```bash
# Fetch URLs for a domain
gau example.com

# Include subdomains
gau --subs example.com

# Specify data providers
gau --providers wayback,otx,commoncrawl example.com

# Output to file
gau example.com | sort -u > urls.txt

# Filter interesting extensions and parameters
gau --subs example.com | grep -E "\.js$|\.php$|\.aspx|\.jsp|\?.*=" | sort -u

# Extract all unique parameters
gau --subs example.com | grep -oP "\?.*?(?= |$)" | sort -u

# Extract only URLs with extension patterns
gau example.com | grep -E "\.(zip|rar|tar|gz|bak|backup|sql|log|env|conf)$"
```

## Common Workflows
```bash
# Full URL discovery pipeline
echo "example.com" | gau --subs --providers wayback,otx,commoncrawl | sort -u > urls.txt

# Find JS files
gau --subs example.com | grep "\.js$" | sort -u > js-files.txt

# Find API endpoints
gau --subs example.com | grep -E "/api/|/graphql|/v[0-9]+/" | sort -u
```
