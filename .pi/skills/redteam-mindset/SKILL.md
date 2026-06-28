---
name: redteam-mindset
description: "Red-team operator discipline: DO NOT STOP primary directive, decision branching (continue despite initial WAF/403), mid-engagement detection awareness, adversary resilience, dual-track coverage (business logic + vulnerability class). Use INSTEAD of standard bug-bounty mindset when target is enterprise/defended."
---

# Red-Team Mindset

## Primary Directive: DO NOT STOP

A patched endpoint or WAF block is NOT a stop signal — it's an invitation to pivot.

### Decision Tree for Blocked Path
```
Initial test → 403/WAF → 3 options:
  1. Same bug class, different endpoint (same target, different surface)
  2. Same target, different bug class (pivot the vulnerability class)
  3. Completely different attack surface (pivot the target entirely)

Only stop the engagement if all 3 are exhausted.
```

### "I'm blocked" ≠ "No findings"
- WAF block on SQLi at /api/search → try SQLi at /api/users
- 403 on /admin → try auth_bypass extension (3000+ techniques)
- Login wall → ask for cookies, try Chrome DevTools, try common creds

## Mid-Engagement Detection Awareness

When testing an enterprise target (SOC present):
- 3+ 500 errors on one endpoint → SOC may see the spike → pivot
- 10+ requests/second → rate limiting + IDS alerts → slow down
- Known CVE exploitation → SOC may have signature → manual bypass
- Account lockout after 3 tries → detect user-facing brute-force → switch to another account

## Dual-Track Coverage

Always test on two axes simultaneously:
- **Axis A (Bug class):** SQLi, XSS, SSRF, IDOR, RCE
- **Axis B (Business logic):** Auth, payments, approvals, data flow

Enterprise targets often have:
- Tight vuln class patching (WAF blocks SQLi) but weak business logic
- Tight frontend controls but weak backend API auth
- Tight login but weak password reset

## Confirmation Discipline
- All findings must pass the 7-Question Gate (see bb-methodology)
- No "theoretical" findings — if you can't reproduce it in 2 requests, drop it
- No "maybe" findings — uncertainty means insufficient evidence
