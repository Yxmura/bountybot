---
name: bb-methodology
description: "Bug bounty hunting methodology: 6-phase non-linear workflow (recon > map & rank > hunt > validate > report). Scope enforcement discipline, chain-first mindset, 7-question finding gate, report severity formula. Use as the core methodology for any bug bounty engagement."
---

# Bug Bounty Methodology

## 6-Phase Workflow

Phase transition is non-linear — you can jump back and forth between phases.

### Phase 1: Recon
- Subdomain enumeration: subfinder, crt.sh, DNS brute-force
- HTTP probing: httpx, whatweb
- Port scanning: naabu, nmap top 1000
- Tech stack identification: whatweb, wappalyzer
- JS crawling: katana, manual JS analysis
- Secrets scanning: secret_scanner on JS bundles

### Phase 2: Map & Rank
- Document all endpoints with technologies
- Rank by attack surface:
  - P1: Admin panels, auth pages, APIs, GraphQL
  - P2: User-facing features (search, profile, upload)
  - P3: Marketing pages, static content, docs
- Identify auth requirements per endpoint

### Phase 3: Hunt
- One bug class at a time. Do NOT spray test 10 classes on 50 endpoints.
- Per-class work: use the hunt-* skill (e.g. hunt-xss for XSS testing)
- Log every vector tested via findings_context log
- On confirmed finding, check for chains immediately before moving on
- 20-min rotation: ask "am I making progress?" If no → rotate class/endpoint

### Phase 4: Validate
- Run the 7-Question Gate before writing ANY report:
  1. Can an attacker use this right now, step by step?
  2. Is the impact on the program's accepted list?
  3. Is the root cause in an in-scope asset?
  4. Does it require privileged access an attacker can't get?
  5. Is this already known or accepted behavior?
  6. Can you prove impact beyond "technically possible"?
  7. Is this on the never-submit list?
- If any question fails → kill the finding
- Calculate CVSS 3.1 BEFORE adding to findings store
- Verify with cvss_calculator decode

### Phase 5: Chain
- Always run findings_context suggest after each finding
- Chains pay 3-10x more than single bugs
- Common high-value chains:
  - Open redirect + OAuth code theft = ATO
  - XSS + CSRF on admin panel = ATO
  - Cache poisoning + XSS = persistent XSS all users
  - SSRF + Metadata = cloud account compromise
  - IDOR + Business Logic = privilege escalation

### Phase 6: Report
- Severity from highest finding CVSS (never inflate)
- Report per platform template (HackerOne, Bugcrowd, Intigriti)
- Unique CVSS per finding (never copy-paste vectors)
- Include reproducible PoC with curl commands
- Apply evidence-hygiene before submitting

## Chain-First Mindset

After finding any bug, immediately ask: "What could chain with this?"
- Reflected XSS alone = Medium. XSS + CSRF on admin = ATO.
- Open redirect alone = discard. Open redirect + OAuth = critical.
- SSRF DNS-only alone = drop. SSRF + metadata = critical.
- Cache poisoning alone = Medium. Cache poisoning + XSS = all users ATO.

## Anti-Inflation Rules

- C:L requires actual data retrieved (file, record, document). Error codes and version numbers are C:N.
- Default to Low. Config issues score 0.0-3.1, not 5.3.
- Severity must match CVSS score: 0=info, 1.0-3.9=low, 4.0-6.9=medium, 7.0-8.9=high, 9.0-10.0=critical.
- When in doubt, round down.

## Pre-Submit Checklist

- [ ] 7-Question Gate passed
- [ ] CVSS calculated and verified via decode
- [ ] Severity matches CVSS range
- [ ] In scope (verified against program scope)
- [ ] Working PoC (curl command included)
- [ ] Evidence captured and sanitized (see evidence-hygiene)
- [ ] Not a duplicate (searched HackerOne Hacktivity)
- [ ] Not on never-submit list
