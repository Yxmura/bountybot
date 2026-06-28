---
name: evidence-hygiene
description: "Evidence-capture and PoC-redaction discipline for bug-bounty submissions: cookie redaction protocol (which fields to mask), PII black-bar discipline (what to mask vs leave visible), HAR file sanitization, screenshot hygiene, filename conventions. Use BEFORE any PoC screenshot, BEFORE attaching a HAR, or whenever preparing evidence with session cookies or other-user PII."
---

# Evidence Hygiene — PoC Capture & Redaction Discipline

Use this skill BEFORE capturing any screenshot, exporting any HAR, or attaching any evidence. It catches the most common mistakes that cause cookie leaks, PII exposure, or rejected reports.

## 1. What to Mask vs Leave Visible

| Category | Examples | Treatment |
|---|---|---|
| **Your session secrets** | Session cookies, OAuth tokens, refresh tokens, API keys | Always redact |
| **Other users' PII** | Real names, emails, phone numbers, addresses, account IDs | Redact unless directly demonstrating impact |
| **Triager-useful metadata** | Trace IDs, request IDs, server timestamps, test account UID | Leave visible — helps triager correlate |
| **Test passwords** | Throwaway passwords | Acceptable if rotated after submission |

## 2. Cookie Redaction Protocol

Mask these in every screenshot:
- Session cookie value (`session=******`)
- `Authorization: Bearer ******`
- `Set-Cookie` response header values
- CSRF tokens bound to your session

Do NOT mask (leave for triager):
- Cookie names and structure
- Domain, path, expires, httponly, samesite flags
- Response status codes and timing

## 3. PII Black-Bar Discipline

Mask in screenshots:
- Real names → "[REDACTED NAME]"
- Email addresses → `u***@***.com`
- Phone numbers → Show last 4 digits only
- Profile photos → Blur faces
- Street addresses → Show city/country only

Leave visible (useful to triager):
- Usernames (test accounts)
- User IDs (not PII alone)
- Request/response bodies showing the vulnerability
- Trace/request IDs

## 4. Screenshot Capture Order

1. HTTP request (curl command or Burp Repeater) — cookie values masked
2. HTTP response — vulnerability evidence visible
3. Browser proof — URL bar showing the domain + vulnerable page
4. Impact demonstration — data accessed, action completed

File naming: `{bug-class}_{endpoint}_{descriptor}.png`

## 5. HAR File Sanitization

Before attaching HAR files, strip:
- Cookie headers (both request and response)
- Set-Cookie headers
- Authorization headers

jq filter for HAR sanitization:
```bash
jq 'del(.log.entries[].request.headers[] | select(.name | test("cookie|authorization"; "i"))) | del(.log.entries[].response.headers[] | select(.name | test("set-cookie"; "i")))' capture.har > sanitized.har
```

## 6. PoC Checklist (60-second pre-submit)

- [ ] Session cookies masked
- [ ] Other-user PII redacted
- [ ] No real credentials exposed
- [ ] URL bar visible in browser screenshots
- [ ] HAR sanitized (Cookie/Authorization removed)
- [ ] File named: `{class}_{endpoint}_poc.png`
- [ ] Screenshot shows the actual impact (not just a 200 status)
