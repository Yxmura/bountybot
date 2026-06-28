---
name: dalfox
description: "Dalfox Skill — security tool usage guide for bug bounty hunting"
---

# Dalfox Skill

Dalfox is a powerful XSS (Cross-Site Scripting) scanner with parameter analysis and DOM-based XSS detection.

## Installation
```bash
go install github.com/hahwul/dalfox/v2@latest
```

## Basic Usage
```bash
# Scan a single URL
dalfox url https://example.com/page?param=value

# Scan URLs from file
dalfox file urls.txt

# Pipeline from gau
gau example.com | grep "?" | dalfox pipe

# Custom payload
dalfox url https://example.com?q=test --custom-payload '"><svg onload=alert(1)>'

# Use specific payload type
dalfox url https://example.com?q=test --trigger-type reflected

# Headless mode (for DOM XSS)
dalfox url https://example.com?q=test --headless

# Silent output
dalfox url https://example.com?q=test --silence

# Output to file
dalfox url https://example.com?q=test -o results.txt
```

## Common Workflows
```bash
# Scan all URLs with parameters
gau example.com | grep "?" | dalfox pipe --silence

# Scan with custom headers
dalfox url https://example.com --header "Cookie: session=xxx"

# Focused scan with specific payload
dalfox url "https://example.com/search?q=FUZZ" --custom-payload '"><script>alert(1)</script>'
```
