---
name: hunt-cors
description: "Hunting skill for CORS misconfigurations. Origin reflection, wildcard origin with credentials, preflight bypass, null origin misconfig, CORS + CSRF chains. Use when testing API endpoints that should be protected by CORS policy."
---

# Hunt: CORS Misconfiguration

## Detection Patterns

### Origin Reflection
```
GET /api/sensitive-data
Origin: https://attacker.com
Response: Access-Control-Allow-Origin: https://attacker.com
         Access-Control-Allow-Credentials: true
```
If server reflects arbitrary Origin with credentials → exfiltrate data cross-origin.

### Wildcard Origin with Credentials
```
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```
This is invalid per spec — browser blocks credentialed requests to wildcard. But testing is still valuable to confirm.

### Preflight Bypass
```
GET /api/data
Origin: null
```
Some servers set ACAO: null for sandboxed iframes.
Test with sandboxed iframe via `data:` URI.

### Trusted Origin Prefix Matching
```
Origin: https://attacker.com (not trusted)
→ ACAO: null  (blocked)
Origin: https://trusted-target.com.attacker.com
→ ACAO: https://trusted-target.com.attacker.com
```
Check: does server use prefix/suffix match instead of exact? e.g., `.target.com` matching `attacker.com.target.com`.

### CORS + CSRF
CORS alone isn't a vulnerability. It becomes one when combined with:
- Authenticated state-changing endpoints
- Sensitive data accessible cross-origin
- Credential-bearing requests

## Confirmation Gates
- Sensitive data accessible from attacker origin → confirmed + high
- Credential-bearing CORS request succeeds → confirmed + high
- CORS misconfig + no CSRF protection → cross-origin state change

## Chain Templates
- CORS + Sensitive API → exfiltrate PII cross-origin
- CORS + CSRF → force state change from attacker's site
- CORS + XSS → bypass origin restrictions via injected code
