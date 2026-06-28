# Bug Bounty Agent — Complete Tool Reference

## Core Investigation Store

### findings_context — Central Investigation Notebook (Source of Truth)

```
findings_context(action="set-target", title="example.com")
findings_context(action="log", message="Port 8443 discovered with self-signed cert")
findings_context(action="flag", endpoint="/admin/test", reason="Interesting access control")
findings_context(action="add", title="Reflected XSS in Search", severity="high", type="xss", endpoint="https://example.com/search", cwe="CWE-79", description="...", poc="...", cvssScore=6.1, cvssVector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")
findings_context(action="list", severityFilter="critical,high")
findings_context(action="status")
findings_context(action="get", findingId="F-XXX")
findings_context(action="update", findingId="F-XXX", cvssScore=8.5, severity="high")
findings_context(action="suggest")                                 # chain recommendations
findings_context(action="chain-add", findingId="F-XXX", chainWith="F-YYY,F-ZZZ")
findings_context(action="check-policy")                            # cross-reference findings against policy
findings_context(action="set-policy", policyPath="./policy.md")    # load company security policy
findings_context(action="timeline")                                # investigation history
findings_context(action="export")                                  # full data dump for reporting
findings_context(action="clear")
findings_context(action="phase")                                   # advance to next phase
findings_context(action="phase", phase="exploitation")             # jump to specific phase
```

Stored in `.trapframe/findings.json` — persistent across sessions.

## Extension Tools (15 + Chrome DevTools + Burp)

### cvss_calculator — CVSS 3.1 Scoring (Full Spec)

```
cvss_calculator(action="base", av="N", ac="L", pr="N", ui="R", s="C", c="L", i="L", a="N")
cvss_calculator(action="temporal", av="N", ac="L", pr="N", ui="N", s="C", c="H", i="H", a="N", e="F", rl="O", rc="C")
cvss_calculator(action="environmental", av="N", ac="L", pr="N", ui="N", s="C", c="H", i="H", a="N", cr="H", ir="M", ar="L", mav="X", mac="X")
cvss_calculator(action="decode", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")
cvss_calculator(action="quick", severity="high", findingType="sqli")
```

Implements exact CVSS 3.1 formulas with correct `roundup()`. Supports base, temporal, and environmental scores.

### auth_bypass — 403/401 Bypass (3000+ Techniques)

```
auth_bypass(url="https://example.com/admin")
auth_bypass(url="https://example.com/api", module="headers")
auth_bypass(url="https://example.com/secret", module="all", concurrency=30)
```

Modules: `headers`, `verbs`, `paths`, `case`, `encode`, `content-type`, `cookies`, `middle-headers`, `all`

### jwt_analyzer — JWT Security Testing

```
jwt_analyzer(action="analyze", token="eyJhbGciOiJIUzI1NiIs...")
jwt_analyzer(action="verify", token="eyJ...", verifyUrl="https://example.com/api/me")
jwt_analyzer(action="bruteforce", token="eyJhbGciOiJIUzI1NiIs...")
jwt_analyzer(action="bruteforce", token="eyJ...", secretWordlist="dev,test,production,myapp")
```

Tests: algorithm confusion (none/HS256/RS256), claim injection, kid path traversal, jku SSRF, weak HMAC secrets

### http_request — HTTP Client

```
http_request(method="GET", url="https://example.com/api/users")
http_request(method="POST", url="https://example.com/login", headers='{"Content-Type":"application/json"}', body='{"user":"admin","pass":"test"}')
http_request(method="GET", url="https://example.com/js/app.js", extractJsonField="data.version")
```

Automatic cookie jar across requests. Command: `/cookies` to view session cookies.

### payload_tester — Automated Payload Delivery

```
payload_tester(url="https://example.com/search?q=FUZZ", vulnType="xss")
payload_tester(url="https://example.com/api?id=FUZZ", vulnType="sqli")
payload_tester(url="https://example.com/redirect?url=FUZZ", vulnType="open-redirect")
payload_tester(url="https://example.com/load?file=FUZZ", vulnType="lfi")
payload_tester(url="https://example.com/import?url=FUZZ", vulnType="ssrf")
payload_tester(url="https://example.com/render?template=FUZZ", vulnType="ssti")
```

8 vuln classes (sqli, xss, ssti, ssrf, lfi, cmdi, open-redirect, xxe) with confidence scoring and evidence extraction.

### secret_scanner — Secrets Detection

```
secret_scanner(text="<paste response body or file content>")
```

30+ secret patterns: AWS/GC/Azure keys, JWT tokens, private keys, passwords, DB URLs, internal IPs, GitHub tokens, Slack webhooks, Stripe keys, etc.

### recon — Reconnaissance Orchestration

```
recon(target="example.com", scope="quick")
recon(target="example.com", scope="full")
```

### browser_data — Cookies & Storage

```
browser_data(action="cookies", browser="chrome", domain="example.com", format="curl")
browser_data(action="localStorage", browser="all", domain="example.com")
browser_data(action="get", domain="example.com")
browser_data(action="set", domain="example.com", cookies="session=abc123")
```

### notepad — Quick Notes

```
notepad(action="add", text="[recon] Discovered admin.example.com on port 8443")
notepad(action="view")
notepad(action="export", file="findings-today.md")
notepad(action="clear")
```

### report_generator — Platform Reports

```
report_generator(action="template", platform="hackerone")
report_generator(action="generate", platform="intigriti", title="XSS in Search", severity="high", category="xss", description="...", impact="...", steps="...", affectedEndpoint="...", remediation="...")
report_generator(action="export", platform="bugcrowd", title="...", severity="critical", ...)
```

### subagent — Delegation

```
subagent(agent="recon", task="Enumerate example.com subdomains and probe live hosts")
subagent(agent="webapp-analyzer", task="Analyze JS bundles and OAuth flow on example.com")
subagent(agent="fuzzer", task="Directory bust and parameter fuzz example.com")
subagent(agent="exploit", task="Analyze this IDOR finding on /api/users/:id")
subagent(agent="chain-hunter", task="Find exploit chains among all current findings")
subagent(agent="verify", task="Verify and score finding F-XXX with CVSS 3.1, check policy")
subagent(agent="report", task="Write a HackerOne report for all verified findings")
```

### scope_enforcer — Deterministic Scope Checking

```
scope_enforcer(action="load", policyPath="./.pi/policy.md")
scope_enforcer(action="check", endpoint="https://api.target.com/users")
scope_enforcer(action="check", target="admin.target.com")
```

Deny wins: an out-of-scope match excludes even if in-scope also matches. Default deny: anything not matching in-scope is blocked.

Policy file format:
```
# In Scope
*.target.com
10.0.0.0/8
re:^staging\d+\.target\.com$

# Out of Scope
admin.target.com
*.internal.target.com
```

### Chrome DevTools — Real Browser Automation (stealth-patched)

```
chrome_navigate({ url: "https://example.com" })

```
chrome_navigate({ url: "https://example.com" })
chrome_snapshot()                                               # AX tree with @(x,y) click coordinates
chrome_execute_js({ expression: "document.title" })             # extract data via JS
chrome_screenshot()                                             # visual verification
chrome_click({ x: 150, y: 200 })                                # click at coordinates
chrome_type({ text: "hello" })                                  # type into focused element
chrome_press_key({ key: "Enter" })                              # press a key
chrome_scroll({ direction: "down", amount: 500 })               # scroll
chrome_page_info()                                              # URL, title, viewport
chrome_wait({ duration: 2 })                                    # wait 2 seconds
chrome_wait_for_load()                                          # wait for page load
chrome_list_tabs()                                              # list open tabs
chrome_new_tab({ url: "https://..." })                          # open new tab
chrome_switch_tab({ index: 0 })                                 # switch to tab
chrome_close_tab({ index: 1 })                                  # close a tab
chrome_go_back() / chrome_go_forward() / chrome_reload()        # navigation
chrome_close()                                                  # close browser (auto-relaunches)
```

**Stealth-patched** — uses `playwright-stealth` to patch `navigator.webdriver`, plugin arrays, permissions API, and canvas fingerprinting. Bypasses Akamai, Cloudflare, Imperva bot detection out of the box.

**Lazy-launch** — Chrome starts on first tool call. Persistent profile at `~/.chrome-dev-tools/profile` preserves cookies and logins across sessions.

**Always use Chrome for:**
- Targets returning WAF challenges (Cloudflare "Checking your browser", Imperva block pages)
- JavaScript-heavy SPAs (React, Vue, Angular) where `http_request` returns empty shells
- Pages requiring rendered DOM inspection
- Capturing screenshots for bug reports
- Form interaction and multi-step authenticated workflows

**Use `http_request` for:**
- Simple API calls (REST endpoints, JSON responses)
- Quick parameter testing on non-protected endpoints
- Recon when Chrome is overkill

## Subagents (7 — in .pi/agents/)

| Agent | Role | Key Tools | Use When |
|-------|------|-----------|----------|
| **recon** | Subdomain enum, HTTP probing, tech stack, crawling | bash (subfinder, httpx, katana, nuclei), secret_scanner | First step on any target |
| **webapp-analyzer** | JS analysis, source maps, OAuth/OIDC, auth flows | bash (whatweb, jwt_tool), secret_scanner, jwt_analyzer | JS-heavy apps, OAuth flows |
| **fuzzer** | Directory busting, parameter mining, WAF evasion | bash (ffuf, nuclei), auth_bypass, payload_tester | After surface mapping |
| **exploit** | SQLi, XSS, SSRF, RCE, auth bypass, business logic | bash (sqlmap, dalfox), http_request, payload_tester, jwt_analyzer, auth_bypass | On flagged endpoints |
| **chain-hunter** | A->B chains, impact amplification | findings_context, cvss_calculator, http_request | After multiple findings |
| **verify** | CVSS 3.1 scoring, CWE mapping, policy compliance | cvss_calculator, findings_context | Before every report |
| **report** | Platform-formatted reports with PoCs | findings_context, cvss_calculator, report_generator | After verification |

### burp_client — Burp Suite REST API Integration

```
burp_client(action="check")                                              # verify Burp API is running
burp_client(action="send", url="https://target.com/api", method="GET")   # send through Burp Repeater
burp_client(action="collaborator")                                       # get Burp Collaborator interactions
burp_client(action="scope")                                              # get/check Burp target scope
burp_client(action="history", maxEntries=50)                             # view proxy history
```

**Requires:** Burp Suite Professional with REST API on port 1337 (or BURP_API_URL env var). Use for blind XSS/SSRF via Collaborator, capturing traffic for manual review, and using Burp extensions alongside Pi.

## Skills (34 — in .pi/skills/)

**Methodology:** `bb-methodology` `trapframe` (state machine approach, 6-phase workflow, 7-question gate, anti-inflation)

**Evidence & Reporting:** `evidence-hygiene` (cookie redaction, PII masking, HAR sanitization, screenshot order)

**Web App Hunting (per-class from H1 patterns):**
- `hunt-xss` (174 disclosed reports) — Reflected, stored, DOM, blind XSS, WAF bypass
- `hunt-sqli` — Error-based, union, blind/time-based, second-order, NoSQL
- `hunt-ssrf` — Cloud metadata (AWS/GCP/Azure), internal services, filter bypasses
- `hunt-idor` — Horizontal/vertical, UUID enumeration, mass assignment
- `hunt-rce` — Command injection, SSTI, deserialization, upload RCE
- `hunt-ato` — Password reset, OAuth theft, MFA bypass, SAML attacks
- `hunt-oauth` — redirect_uri bypass, state CSRF, PKCE, implicit flow leakage
- `hunt-jwt` — Algorithm confusion, kid injection, jku SSRF, brute-force
- `hunt-file-upload` — RCE, SVG XSS, path traversal, XXE, MIME bypass
- `hunt-business-logic` — Race conditions, balance manipulation, 2FA flaws
- `hunt-graphql` — Introspection, batching attacks, injection, mutation abuse
- `hunt-csrf` — Token validation flaws, SameSite bypass, header bypass, login CSRF
- `hunt-cors` — Origin reflection, wildcard+creds, preflight bypass, prefix matching
- `hunt-cache-poison` — Unkeyed headers, cache key filler, host header, cache deception
- `hunt-http-smuggling` — CL.TE, TE.CL, TE.TE, WAF bypass via smuggling
- `hunt-lfi` — Path traversal, PHP wrappers, log poisoning, RFI
- `hunt-ssti` — Jinja2, Twig, Freemarker, Velocity, Jade, Handlebars detection+RCE
- `hunt-xxe` — In-band, blind OOB, cloud metadata, SVG upload, DOCX
- `hunt-deserialization` — PHP/Java/.NET/Python/Node.js gadget chains
- `hunt-host-header` — Password reset poisoning, cache poison, routing SSRF
- `hunt-websocket` — CSWSH, unauthenticated access, message injection
- `hunt-nosqli` — MongoDB `$ne`/`$regex`/`$where`, blind extraction

**Enterprise Platforms:**
- `enterprise-m365-entra` — AAD enumeration, password spray, MFA bypass, PRT theft
- `enterprise-vcenter` — vCenter CVE chains (2024-2026), SSO bypass, ESXi takeover
- `enterprise-vpn` — Cisco ASA, Fortinet, Citrix, Ivanti, Palo Alto, F5 CVE targeting
- `enterprise-sharepoint` — NTLM relay, SOAP abuse, ToolShell, workflow abuse
- `enterprise-cloud-iam` — AWS role chaining, GCP SA impersonation, Azure MSI

**Red Team & OSINT:**
- `redteam-mindset` — DO NOT STOP discipline, blocked-path pivoting, SOC evasion, dual-track
- `osint-methodology` — Domain recon, cert transparency, GitHub dorking, cloud discovery
- `supply-chain-recon` — CDN/takeover/3rd-party dependency analysis, service workers

**Reporting:** `report-writing` — report structure, severity justification, business impact, pre-submit checklist

**Recon:** `subfinder` `httpx` `gau` `amass` `katana` `naabu` `shodan`

**Fuzzing:** `ffuf` `feroxbuster` `arjun`

**Vuln Scanning:** `nuclei` `dalfox` `sqlmap` `wafw00f`

**Specialized:** `jwt_tool` `gitleaks`

## Workflow Prompts (in .pi/prompts/)

- `/full-recon` — Complete recon workflow (subdomain -> HTTP -> nuclei -> URLs -> notes -> report)
- `/quick-scan` — Fast triage (subfinder + httpx + critical/high nuclei only)

## Policy Integration

```
findings_context(action="set-policy", policyPath="./policy.md")
findings_context(action="check-policy")
```

Policy file format: markdown listing in-scope vuln types, severity thresholds, CWEs, and compliance requirements. Findings are cross-referenced and flagged if out of scope.

## The Finding -> Report Pipeline

```
find vuln -> cvss_calculator base (unique per finding) -> cvss_calculator decode (verify) -> findings_context add (with cvssScore + cvssVector + severity + poc + description)
  -> findings_context suggest -> subagent chain-hunter -> findings_context chain-add (ONLY if chain PoC works)
  -> subagent verify (scope check + CVSS decode + severity match + CWE map + policy check) -> findings_context update
  -> subagent report / report_generator export (filtered to in-scope only)
```

**Order is strict:** CVSS must be calculated BEFORE adding a finding. Never add a finding without a CVSS score and vector. The `add` action will reject findings missing cvssScore, cvssVector, severity, or poc.

## Critical Triage Rules

- Theoretical bugs are NOT bugs. Prove state mutation or drop it.
- Open redirect alone = discard (use only as chain entry primitive)
- SSRF with DNS-only callback = not reportable (escalate or drop)
- Source maps without secrets = parse for routes, don't report
- `findings_context(action="log")` after EVERY test — even dead ends
- Always verify CVSS via `cvss_calculator(action="decode")` before reporting
- Chains pay 3-10x more — always run chain-hunter before reporting
- **Scope check first:** A wildcard `*.example.com` does NOT include assets explicitly listed as out of scope. Check before testing and before reporting.
- **Unique CVSS per finding:** Never copy-paste the same vector. Every finding has unique CIA impact.
- **Severity matches CVSS:** Score 1.0-3.9 = Low, 4.0-6.9 = Medium, 7.0-8.9 = High, 9.0-10.0 = Critical. If CVSS says 5.3, severity is Medium, not Low.
- **WAF blocked? Ask for cookies:** If a target returns a WAF challenge (Imperva, Cloudflare), stop probing and ask the user for a session cookie/Bearer token via `browser_data(action="set")`.
- **Phase tracking:** Log `phase:recon`, `phase:fuzzing`, `phase:exploitation`, `phase:chaining`, `phase:verification`, `phase:reporting` via findings_context. Always know what phase you're in.
- **Evidence with every finding:** poc field must contain the exact curl command. description must include request/response data. Never add a finding with empty evidence.
- **CVSS before add:** Never add a finding without first calculating its CVSS score. Order: exploit -> cvss base -> decode verify -> findings add.
- **No no-op calls:** `findings_context update` must specify findingId and at least one changed field. Use `status` to just check state.
- **Check tools first:** Verify CLI tools exist (`which`). If missing, use alternatives (curl, http_request).
- **Report severity from data:** Highest finding CVSS determines report severity. Never inflate.
- **Dead-end logging:** After 5-10 payloads with no signal, log the dead end. Never re-test.
- **Respect RoE:** Max 5 req/sec. No automated scanners if forbidden. Stop after 3 consecutive errors on an endpoint.
- **Anti-inflation: default to Low:** C:L requires actual data retrieved (file, record, document). Error codes and version numbers are not C:L. Pure config issues score 0.0-3.1, not 5.3. When in doubt, round down.
- **Use Chrome for bot-protected sites:** If a target returns Cloudflare/Akamai/Imperva challenge, CAPTCHA, or requires JS — use `chrome_navigate`, not `http_request`. Chrome DevTools has built-in stealth patches.
- **No fabricated output:** Only report what tools actually returned. Quote raw response data. No paraphrasing into something more favorable.
- **Exhaust before zero:** Before declaring no findings: enumerate subs (2+ sources), probe all hosts, crawl depth 2+, dirbust, param mine, test top 5 vuln classes. Log each step.
- **Admit when blocked:** Say "I am blocked. I need X to continue." Log as BLOCKED. Don't skip silently or fabricate.
- **Chain PoC required:** Theoretical chains don't escalate severity. Validate each link with a working PoC before updating severity.
- **Quote leaked data:** Finding description must include the exact response data retrieved. "Leaks sensitive data" is not evidence. Show the actual bytes.
