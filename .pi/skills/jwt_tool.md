---
name: jwt-tool
description: "jwt_tool — JWT security testing tool for bug bounty hunting"
---

# jwt_tool Skill

JWT Tool tests JWTs for common vulnerabilities: algorithm confusion, weak HMAC secrets, kid injection, and more.

## Installation
```bash
git clone https://github.com/ticarpi/jwt_tool.git
cd jwt_tool
pip install -r requirements.txt
```

## Basic Usage
```bash
# Analyze a token (no attack)
python3 jwt_tool.py <token>

# Scan for common vulnerabilities
python3 jwt_tool.py <token> -M at

# Test none algorithm (alg:none)
python3 jwt_tool.py <token> -X a

# Brute-force HMAC secret
python3 jwt_tool.py <token> -C -d /path/to/wordlist.txt

# Test kid injection
python3 jwt_tool.py <token> -T

# Test JWKS spoofing
python3 jwt_tool.py <token> -X s

# Sign with known key
python3 jwt_tool.py <token> -S hs256 -p "secret_key"

# Tamper with claims
python3 jwt_tool.py <token> -I -pc username -pv admin
```

## Common Tests
```bash
# Full vulnerability scan
python3 jwt_tool.py <token> -M at -t https://example.com/api

# Quick check: none algorithm
python3 jwt_tool.py <token> -X a

# Quick check: empty HMAC
python3 jwt_tool.py <token> -X n
```
