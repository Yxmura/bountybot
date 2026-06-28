# bountybot

**Autonomous bug bounty hunting agent for [Pi](https://pi.dev).**

Drop-in .pi/ directory that turns Pi into a purpose-built bug bounty hunter with 34 skills, 15 extensions, stealth Chrome, CVSS 3.1 verification, and anti-inflation enforcement.

## Features

- **34 hunt skills** — XSS, SQLi, SSRF, IDOR, RCE, ATO, JWT, GraphQL, XXE, SSTI, file upload, deserialization, websocket, NoSQLi, host header, cache poison, HTTP smuggling, CSRF, CORS, OAuth, and more
- **5 enterprise platform skills** — M365/Entra, vCenter, VPN (Cisco/Fortinet/Citrix), SharePoint, Cloud IAM (AWS/GCP/Azure)
- **15 extensions** — CVSS 3.1 calculator (verified against Python lib), findings store with chain discovery, rate-limited HTTP client, scope enforcer, Burp Suite REST API client, secret scanner, JWT analyzer, payload tester, auth bypass, report generator, and more
- **Stealth Chrome** — Bypasses Akamai, Cloudflare, Imperva via playwright-stealth patches
- **Anti-inflation enforcement** — Code-level CVSS score vs severity validation, not prompt rules
- **7 subagents** — Recon, exploit, verify, report, fuzzer, chain-hunter, webapp-analyzer
- **Eval framework** — Automated headless testing against JuiceShop, PortSwigger labs
- **Rate limiting** — 200ms between requests built into HTTP client

## Quick Start

```bash
# Install Pi (if you haven't)
npm install -g @earendil-works/pi-coding-agent

# Clone bountybot
git clone https://github.com/Yxmura/bountybot.git
cd bountybot

# Run Pi — it auto-discovers .pi/ extensions, skills, and agents
pi
```

### Headless / Automated

```bash
pi -p "Recon target.com: find subdomains, endpoints, and check for CVEs"
pi -p "Check https://example.com for XSS, SQLi, and SSRF vulnerabilities"
```

## Architecture

```
bountybot/
├── .pi/
│   ├── SYSTEM.md           # Master agent prompt (38 critical rules)
│   ├── APPEND_SYSTEM.md     # Full tool/skill reference
│   ├── extensions/          # 15 deterministic tools (TS)
│   │   ├── cvss-calculator/ # CVSS 3.1 base + temporal + environmental
│   │   ├── findings-context/ # Centralized findings store with chain detection
│   │   ├── http-client/     # Rate-limited requests (200ms)
│   │   ├── scope-enforcer/  # Deterministic scope checking (deny wins)
│   │   ├── burp-client/     # Burp Suite REST API (collaborator, repeater)
│   │   ├── browser-data/    # Chrome DevTools integration
│   │   └── ...
│   ├── skills/              # 34 knowledge skills (hunt classes, platforms, ops)
│   │   ├── hunt-xss/        # Per-class hunt methodology from H1 patterns
│   │   ├── hunt-sqli/
│   │   ├── enterprise-m365-entra/
│   │   └── ...
│   └── agents/              # 7 subagents with YAML frontmatter
│       ├── recon.md
│       ├── exploit.md
│       ├── chain-hunter.md
│       └── ...
└── eval/                    # Automated evaluation framework
    ├── run_eval.py          # Headless Pi vs JuiceShop/PortSwigger
    ├── portswigger_labs.json # 15 lab definitions
    └── requirements.txt
```

## Requirements

- [Pi](https://pi.dev) v0.80+ (`npm install -g @earendil-works/pi-coding-agent`)
- Node.js >= 22.19
- API key for your chosen LLM provider (OpenAI, Anthropic, Google, etc.)
- Optional: Burp Suite Professional (for Burp REST API integration)
- Optional: Chrome/Chromium (for bot-protected targets via Chrome DevTools)

## Eval

```bash
cd eval
pip install -r requirements.txt
# JuiceShop on port 3000
docker run -d -p 3000:3000 bkimminich/juice-shop
python run_eval.py --target juiceshop
# Or PortSwigger
python run_eval.py --target portswigger --labs portswigger_labs.json
```

## Credits

Built on [Pi](https://github.com/earendil-works/pi) — the open coding agent platform.
