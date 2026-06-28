---
name: ffuf
description: "Ffuf Skill — security tool usage guide for bug bounty hunting"
---

# Ffuf Skill

Ffuf (Fuzz Faster U Fool) is a fast web fuzzer for directory discovery, parameter fuzzing, and virtual host enumeration.

## Installation
```bash
go install github.com/ffuf/ffuf/v2@latest
```

## Directory/File Discovery
```bash
# Basic directory fuzzing
ffuf -u https://example.com/FUZZ -w /path/to/wordlist.txt

# File extension fuzzing
ffuf -u https://example.com/index.FUZZ -w /path/to/extensions.txt

# Filter by status code
ffuf -u https://example.com/FUZZ -w wordlist.txt -mc 200,301

# Filter by response size
ffuf -u https://example.com/FUZZ -w wordlist.txt -fs 0
```

## Parameter Discovery
```bash
# GET parameter fuzzing
ffuf -u 'https://example.com/page?FUZZ=test' -w /path/to/params.txt -fs 1234

# POST parameter fuzzing
ffuf -u https://example.com/api -X POST -d 'FUZZ=test' -w params.txt -fs 0
```

## Virtual Host Discovery
```bash
ffuf -u https://example.com -H "Host: FUZZ.example.com" -w subdomains.txt -fs 1234
```

## Key Options
- `-u` — Target URL with FUZZ keyword
- `-w` — Wordlist path
- `-mc` — Match HTTP status codes
- `-fc` — Filter HTTP status codes
- `-fs` — Filter by response size
- `-fw` — Filter by word count
- `-H` — Custom headers
- `-X` — HTTP method
- `-d` — POST data
- `-o` — Output file
- `-of` — Output format (json, csv, ejson, html, md)
- `-t` — Number of threads
- `-recursion` — Follow directories recursively

## Common Wordlists
- `/usr/share/wordlists/dirb/common.txt`
- `/usr/share/seclists/Discovery/Web-Content/`
- SecLists GitHub: https://github.com/danielmiessler/SecLists

## Security Notes
- Respect rate limits — use `-t` to control threads
- Add delay with `-p` to avoid rate limiting
- Some targets may block after many 404s — start with `-mc 200,204,301,302,307,401,403,405`
