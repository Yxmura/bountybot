---
name: hunt-cache-poison
description: "Hunting skill for Web Cache Poisoning and Web Cache Deception vulnerabilities. Unkeyed header injection, cache key confusion, cache deception via file extension. Use when testing CDN-cached or reverse-proxy-cached endpoints."
---

# Hunt: Web Cache Poisoning / Deception

## Detection

### Cache vs No-Cache Responses
```
GET /page  → X-Cache: hit
GET /page  → X-Cache: miss
```
Identify cached endpoints. CDN headers: `X-Cache`, `CF-Cache-Status`, `Age`, `X-Served-By`.

## Cache Poisoning Attack Vectors

### Unkeyed Header Injection
```
GET /page
X-Forwarded-Host: attacker.com
→ Response contains URL pointing to attacker.com
→ Cache serves malicious response to all users
```
Test: `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Scheme`, `Origin`, `X-Original-URL`.

### Cookie-Based Cache Poisoning
```
GET /page
Cookie: session=123
```
If cookie affects response but is not in cache key → one user's personalized response serves to another.

### Cache Key Filler
```
GET /page?utm_campaign=asdf1234
```
Parameter is in cache key but doesn't affect response:
- Add random param every request → fills cache with variations → DoS via cache key bloat

### Host Header Injection
```
GET /page
Host: attacker.com
→ Redirect to attacker.com
→ Cache serves redirect to all users
```

## Cache Deception

### File Extension Confusion
```
GET /account/settings/nonexistent.css
```
CDN caches response as static CSS file. If origin returns dynamic content (HTML with auth data) with `Content-Type: text/css`, the sensitive data is served from cache to anyone requesting it.

### Normalization Bypass
```
GET /api/users
GET //api/users
GET /api/Users
```
If cache treats these as different URLs but origin serves same content → cache deception.

## Confirmation Gates
- Unkeyed header changes response content → confirmed + high
- Poisoned response served to second request (X-Cache: hit) → confirmed + critical
- Cache deception returns user-specific data → confirmed + high

## Chain Templates
- Cache Poisoning (unkeyed header) + XSS → persistent XSS for all cached users
- Cache Poisoning (host header) + Open Redirect → all users redirected to malicious site
- Cache Deception + IDOR → user-specific data served to all cache consumers
