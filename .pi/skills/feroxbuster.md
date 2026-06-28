---
name: feroxbuster
description: "Feroxbuster Skill — security tool usage guide for bug bounty hunting"
---

# Feroxbuster Skill

Feroxbuster is a fast content discovery tool written in Rust. Similar to dirbuster/gobuster but significantly faster.

## Installation
```bash
# Download binary from GitHub releases
# https://github.com/epi052/feroxbuster/releases
# Or use cargo:
cargo install feroxbuster
```

## Basic Usage
```bash
# Basic scan with common wordlist
feroxbuster -u https://example.com

# Custom wordlist
feroxbuster -u https://example.com -w /path/to/wordlist.txt

# Follow redirects
feroxbuster -u https://example.com -r

# Filter by status codes
feroxbuster -u https://example.com -C 404,400

# Match status codes only
feroxbuster -u https://example.com -m 200,301,302,403

# Extensions
feroxbuster -u https://example.com -x php,html,js,json,txt,asp,aspx,jsp

# Parallelism
feroxbuster -u https://example.com -t 50

# Recursion
feroxbuster -u https://example.com -d 3

# Include headers
feroxbuster -u https://example.com -H "Cookie: session=xxx"

# Silent output
feroxbuster -u https://example.com --silent

# JSON output
feroxbuster -u https://example.com -o results.json --json
```

## Wordlists
- `/usr/share/seclists/Discovery/Web-Content/common.txt`
- `/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt`
- `/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt`
- SecLists: https://github.com/danielmiessler/SecLists
