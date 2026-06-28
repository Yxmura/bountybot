---
name: hunt-host-header
description: "Hunting skill for Host Header Injection vulnerabilities. Password reset poisoning, cache poisoning via Host header, SSRF via Host, routing-based SSRF (absolute URL in Host). Use when testing endpoints that use the Host header to construct URLs."
---

# Hunt: Host Header Injection

## Detection

```
GET / HTTP/1.1
Host: attacker.com
```
If response contains `attacker.com` in:
- Redirect URL (Location header)
- In-page links (base href, form action)
- Script/Style includes
- Password reset links in email (stored + sent later)

## Attack Vectors

### Password Reset Poisoning
```
POST /password-reset
Host: attacker.com
```
Server generates: `https://attacker.com/reset?token=abc123`
Attacker sends victim the link, token goes to attacker → ATO.

### Cache Poisoning (via Host)
```
GET /page
Host: attacker.com
→ Response: <link>https://attacker.com/static.js</link>
→ Cache serves malicious page to all users
```

### Absolute URL SSRF
```
GET https://internal-admin/reset HTTP/1.1
Host: attacker.com
(if proxy forwards absolute URL to internal backend)
```

### Routing-Based SSRF
```
Host: localhost:8080
Host: 169.254.169.254
```
If load balancer routes based on Host → SSRF.

## Confirmation Gates
- Host header reflected in response → confirmed + high
- Password reset link uses attacker domain → confirmed + critical
- Cache-layer redirect to attacker → confirmed + critical

## Chain Templates
- Host Header + Password Reset → ATO via poisoned reset link
- Host Header + Cache Poison → persistent redirect to attacker domain
- Host Header + SSRF → access internal endpoints via Host value
