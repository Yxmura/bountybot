---
name: hunt-csrf
description: "Hunting skill for Cross-Site Request Forgery (CSRF) vulnerabilities. CSRF token validation flaws, anti-CSRF header bypass, same-site cookie bypass, CORS+CSRF chains, login/logout CSRF. Use when testing state-changing endpoints."
---

# Hunt: CSRF

## Detection Patterns

### Missing CSRF Token
```
POST /api/users/delete
Cookie: session=valid
```
No anti-CSRF token required. If action executes → CSRF.

### CSRF Token Validation Bypass
```
- Remove token → still accepted
- Change token to arbitrary value → still accepted
- Reuse token from another user → still accepted
- Use expired token → still accepted
- Token validation only on POST but endpoint accepts GET
```

### Header-Based CSRF (including custom header bypass)
```
X-Requested-With: XMLHttpRequest  # often checked
→ Remove header → still accepted
→ Change header value → still accepted
```

### SameSite Cookie Bypass
```
SameSite=Strict → bypass via subdomain → POST to subdomain endpoint
SameSite=Lax → bypass via GET request → state change via GET
```

### Login/Logout CSRF
```
<img src="https://target.com/logout"> → logs victim out
<img src="https://target.com/change-email?email=attacker@evil.com"> → changes email
```
Login CSRF: force victim to log into attacker's account → track victim's actions.

## Confirmation Gates
- State-changing action executed with no CSRF token → confirmed + high
- Token validation bypassed → confirmed + high
- GET request changes state → confirmed + high
- Logout CSRF works → confirmed + medium

## Chain Templates
- CSRF + XSS → bypass CSRF protection via XSS + force state change
- CSRF + IDOR → force state change on another user's data
- Login CSRF + Stored XSS → capture victim's actions after forced login
