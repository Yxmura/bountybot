---
name: report-writing
description: "Bug bounty report writing discipline. Report structure per platform (HackerOne, Bugcrowd, Intigriti), title formula, severity justification from CVSS, business impact phrasing, remediation recommendations, PII redaction. Use BEFORE submitting any report."
---

# Report Writing

## Report Structure (Platform-Agnostic)

### Title Formula
```
[VULN CLASS] in [ENDPOINT] allows [ACTOR] to [IMPACT]
```
Examples:
- Reflected XSS in /api/search allows attacker to execute arbitrary JS in victim's browser
- IDOR in /api/users/:id allows unauthenticated read of any user's PII
- SQL Injection in /api/products allows extraction of entire user database

### Finding Sections (every finding)
1. **Title** — clear, specific, not generic
2. **Severity** — from CVSS (never manually set)
3. **CVSS Vector** — full vector string
4. **CVSS Score** — numerical score
5. **Endpoint** — full URL with parameters
6. **CWE** — standard identifier
7. **Description** — 2-3 sentence technical explanation
8. **Steps to Reproduce** — exact curl commands, step by step
9. **PoC** — working curl commands, HTTP requests
10. **Evidence** — response data showing impact (PII/cookies masked)
11. **Impact** — business consequence (not technical description)
12. **Remediation** — specific fix (not "sanitize input")

## Section Writing Guide

### Description (BAD)
"The application has a reflected XSS vulnerability in the search parameter."

### Description (GOOD)
"The search endpoint at /api/search reflects user-supplied input via the 'q' parameter directly into HTML without sanitization. An attacker can inject arbitrary JavaScript via a payload such as `<img src=x onerror=alert(document.cookie)>`, which executes in any user's browser when they visit the crafted URL."

### Impact (BAD)
"An attacker can execute JavaScript in the victim's browser."

### Impact (GOOD)
"An attacker can hijack any user's active session by exfiltrating their cookies, redirect them to phishing pages, or perform actions on their behalf including password changes and financial transactions. Since the application does not use httpOnly cookies, all session cookies are accessible via cross-site scripting."

### Steps to Reproduce
```bash
curl 'https://target.com/api/search?q=<img src=x onerror=alert(1)>' -H 'Cookie: session=****'
```

### Remediation (BAD)
"Sanitize user input."

### Remediation (GOOD)
"Encode all user-supplied data before inserting into HTML using context-specific encoding. Use Content-Security-Policy headers with a strict nonce-based policy. Set the httpOnly flag on session cookies and implement a proper Content-Type header."

## Platform-Specific Notes

### HackerOne
- CWEs required
- CVSS vector in report
- Severity mapping: Critical ≥9.0, High ≥7.0, Medium ≥4.0, Low ≥0.1

### Bugcrowd
- VRT classification (Vulnerability Rating Taxonomy)
- Priority: P1=Critical, P2=High, P3=Medium, P4=Low, P5=Informational
- Use VRT-aware format for faster triage

### Intigriti
- CVSS 3.1 scoring
- Category, endpoint, description, impact, reproduction, remediation
- Severity: Critical/High/Medium/Low/Info

## Pre-Submission Checklist (60 seconds)
- [ ] Severity matches CVSS range
- [ ] CVSS verified via decode action
- [ ] PoC has working curl command
- [ ] Steps to reproduce clear enough for triager
- [ ] Business impact stated (not technical)
- [ ] Remediation specific and actionable
- [ ] Cookies and PII redacted (see evidence-hygiene)
- [ ] Title follows formula
- [ ] In scope (verified against program page)
