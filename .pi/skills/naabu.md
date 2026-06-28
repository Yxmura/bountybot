---
name: naabu
description: "Naabu Skill — security tool usage guide for bug bounty hunting"
---

# Naabu Skill

Naabu is a fast port scanner by ProjectDiscovery. Useful for finding open services on discovered hosts.

## Installation
```bash
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
```

## Basic Usage
```bash
# Scan a single host
naabu -host example.com

# Scan from hosts file
naabu -list hosts.txt

# Only top ports
naabu -host example.com -top-ports 100

# Silent output
naabu -host example.com -silent

# Output to file
naabu -host example.com -o ports.txt

# Service detection
naabu -host example.com -sV

# All ports (1-65535)
naabu -host example.com -p -

# Specific ports
naabu -host example.com -p 80,443,8080,8443

# Exclude CDN
naabu -host example.com -exclude-cdn

# Rate limiting
naabu -host example.com -rate 1000
```

## Common Pipeline
```bash
subfinder -d example.com -silent | naabu -silent -top-ports 1000 -o open-ports.txt
```
