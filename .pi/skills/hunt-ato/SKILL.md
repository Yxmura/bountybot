---
name: hunt-ato
description: "Hunting skill for Account Takeover (ATO) vulnerabilities. OAuth token theft, password reset abuse, session fixation, brute-force, credential stuffing, MFA bypass, SAML attacks. Use when testing authentication flows."
---

# Hunt: ATO (Account Takeover)

## Detection Patterns

### Password Reset Token
```
POST /password-reset
{"email": "victim@example.com"}  → get token
GET /password-reset?token=abc123  → use token
```
Test: token guessability (short, timestamp-based, sequential, email-encoded).
Test: unvalidated email in reset flow.

### OAuth Token Theft
```
redirect_uri=https://evil.com/callback
```
Test: change redirect_uri to attacker domain. If OAuth sends code/token → ATO.

### Session Fixation
```
GET /login?session=abc123
```
Set session cookie before login, then check if session persists after login → if yes, attacker can pre-set session.

### Credential Stuffing
Test: use known breached passwords on login endpoint.
Check for rate limiting, account lockout, MFA enforcement.

### MFA Bypass
```
- Remove MFA header/param
- Change response from "mfa_required" to "mfa_passed"
- Reuse old MFA token
- Backdoor MFA code (0000, 111111, etc.)
- Use OAuth token after disabling MFA
```

## Auth Bypass Vectors

### Parameter Manipulation
```
POST /api/login → {"admin": false} → change to true
POST /api/2fa/verify → {"code": "123456"} → try common codes, reuse old codes
```

### JWT ATO
See hunt-jwt skill for JWT-specific attacks.

### SAML Attacks
- Signature exclusion: remove `<ds:Signature>` element
- XML signature wrapping: alter SAML assertion content
- Recipient check bypass: change `Destination` URL to attacker's
- XXE in SAML parser

## Password Reset Attack Vectors

### Token Prediction
```
GET /reset?token=1
GET /reset?token=2
GET /reset?token=3
```
If sequential, predictable → ATO via token brute-force.

### Host Header Injection
```
POST /reset
Host: evil.com
```
If server generates reset link with Host header value → attacker gets link.

### Email Parameter Tampering
```
POST /reset
{"email": "victim@example.com"}
→ {"email": "attacker@example.com"}  # change email recipient
```

## Confirmation Gates
- Logged into another user's account → confirmed + critical
- Reset another user's password → confirmed + critical
- Received OAuth token intended for another app → confirmed + high
- Bypassed MFA → confirmed + high

## Chain Templates
- ATO via OAuth + Open Redirect → token theft via redirect_uri manipulation
- ATO via Password Reset + IDOR → reset victim's password via IDOR in email param
- ATO via JWT + Weak Signature → forge admin JWT from user JWT
- ATO via SAML + XXE → read SAML signing key via XXE
