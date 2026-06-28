---
name: katana
description: "Katana Skill — security tool usage guide for bug bounty hunting"
---

# Katana Skill

Katana is a fast crawler by ProjectDiscovery. Discovers endpoints, forms, and JS files from websites.

## Installation
```bash
go install github.com/projectdiscovery/katana/cmd/katana@latest
```

## Basic Usage
```bash
# Crawl a single URL
katana -u https://example.com

# Crawl list of URLs
katana -list urls.txt

# Include JS files in output
katana -u https://example.com -jc

# Include form extraction
katana -u https://example.com -jc -fx

# Silent output (URLs only)
katana -u https://example.com -silent

# Set crawl depth
katana -u https://example.com -d 3

# Output to file
katana -u https://example.com -o crawled.txt

# Pass cookies for authenticated crawling
katana -u https://example.com -H "Cookie: session=xxx"

# Field filtering (only show URLs)
katana -u https://example.com -f url
```

## Common Pipelines
```bash
# Crawl and send to nuclei
katana -u https://example.com -silent | nuclei

# Crawl and extract only JS files
katana -u https://example.com -silent -jc | grep "\.js$"

# Crawl subdomains from subfinder
subfinder -d example.com -silent | httpx -silent | katana -silent
```
