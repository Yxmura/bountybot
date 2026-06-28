---
name: trapframe
description: Trapframe bug bounty hunting methodology - state machine approach to vulnerability discovery
---

# Trapframe Methodology

## Core Philosophy

Software applications are **state machines**. Vulnerabilities are **illegal state transitions** — transitions that violate the intended security model but that the application nonetheless permits.

Every test case is a **state mutation function**: apply an input, observe if the output state violates expectations.

## The Only Question That Matters

"Can an attacker do this RIGHT NOW against a real user who has taken NO unusual actions — and does it cause real harm (stolen money, leaked PII, account takeover, code execution)?"

If the immediate state change is not actionable, discard the current dead-end lead and pivot to an alternative vector. Do not report it as a standalone finding, but retain the discovered telemetry to inform adjacent attack paths.

## Triage Filters (Telemetry vs. Standalone Bugs)

- "Could theoretically allow..." — Not exploitable = not a bug.
- "An attacker with X, Y, Z conditions could..." — Too many preconditions. Dropped.
- "Wrong implementation but no practical impact" — Harmonious non-conformance is not a vulnerability.
- Dead code with a bug in it — Unreachable = zero risk.
- Source maps without secrets — Do not report as a vulnerability; parse them to extract hidden API routes, parameter matrices, and application logic for subsequent exploitation.
- SSRF with DNS-only callback — Do not report unless it can be actively escalated to data exfiltration, internal network mapping, or cloud metadata access.
- Open redirect alone — Discard as a standalone finding; use exclusively as an entry primitive to chain into ATO or OAuth client-secret theft.

## Attack Surface Enumeration

1. **Entry Points** — All URL paths, parameters, headers, cookies, file uploads, API endpoints, websocket connections
2. **State Variables** — Session tokens, CSRF tokens, user roles, shopping carts, balances, request counters
3. **Operations** — Read, create, update, delete, approve, transfer, authenticate, authorize

## Vulnerability Class Mapping

For each operation, test these illegal state transitions:

| Operation | Illegal Transition | Vulnerability Class |
|-----------|-------------------|-------------------|
| Read | A-B data access | IDOR |
| Write | Unvalidated input execution | SQLi, XSS, SSTI |
| Write | State variable overflow | Race condition |
| Auth | Token replay/forgery | JWT none, weak secret |
| Auth | Authentication bypass | SQLi auth bypass, path traversal |
| Auth (OAuth) | Redirect URI bypass | OAuth token theft |
| Cache | Cache + malicious input | Web cache poisoning |
| Any | Parameter injection | SSRF, LFI, command injection |
| Rate-limiting | Excessive operations | Rate limit bypass, race |

## Tool Selection Guide

- **Recon:** subfinder -> httpx -> naabu -> katana -> curl
- **Crawl:** katana -> nuclei (exposures/) -> manual curl
- **Fuzz:** ffuf -> nuclei (fuzzing/) -> manual http_request
- **Exploit SQLi:** nuclei (sqli/) -> manual time-based -> manual union-based
- **Exploit XSS:** manual (context-specific) -> dalfox -> nuclei (xss/)
- **Exploit SSRF:** manual metadata -> internal services -> blind timing
- **Exploit Auth:** jwt_analyzer -> OAuth flow -> password reset -> session analysis
- **Chain:** identify primitives -> find combo vectors -> validate chain PoC
- **Report:** collect structured findings -> cvss_calculator -> report_generator -> output markdown

## Critical Rules

The full 36 critical rules are in `.pi/SYSTEM.md`. Key principles:

1. **No theoretical bugs.** Prove state mutation or drop it.
2. **Zero-finding exit is valid.** But only after exhausting the surface (Rule 33): 2+ subdomain sources, all hosts probed, crawl depth 2+, dirbust, param mine, top 5 vuln classes tested.
3. **No fabricated output.** Only report what tools actually returned. Quote raw data.
4. **CVSS before add.** Calculate score, decode to verify, then add to store. Never add without cvssScore + cvssVector + severity + poc + description.
5. **Anti-inflation.** C:L requires actual data retrieved. Error codes and version numbers are C:N. Default to Low. When in doubt, round down.
6. **Chain PoC required.** Theoretical chains don't escalate severity. Validate each link with a working PoC.
7. **Admit when blocked.** Say "I am blocked. I need X." Don't skip silently or fabricate.
8. **Quote leaked data.** "Leaks sensitive data" is not evidence. Show the actual bytes.

## Efficiency Rules

- Run passive recon simultaneously with active recon
- Use `-silent` and `-json` flags on all ProjectDiscovery tools for machine-parseable output
- Filter noise ruthlessly: ffuf -fs/-fc, httpx -sc, nuclei severity filters
- Cache results: write to files, read from files, avoid redundant scans
- Pivot instantly when a vector shows no signal after 5-10 payloads
