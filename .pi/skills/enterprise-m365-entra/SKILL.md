---
name: enterprise-m365-entra
description: "Enterprise security testing skill for Microsoft 365 and Entra ID (Azure AD). AAD/Entra ID enumeration, password spray, MFA bypass tactics, conditional access policy bypass, OAuth app permissions abuse, device code phishing, token replay, PRT theft. Use when testing M365/Entra ID as identity provider."
---

# Enterprise: Microsoft 365 / Entra ID Security Testing

## Recon Phase

### Domain Verification
Check if target uses M365/Entra ID:
```
nslookup -type=mx target.com          # check for *.mail.protection.outlook.com
nslookup -type=txt target.com          # look for MS=ms XYZ (tenant verification)
https://login.microsoftonline.com/getuserrealm.srf?login=<email>  # returns tenant details
```

### Tenant Enumeration
```
GET https://login.microsoftonline.com/<tenant>/v2.0/.well-known/openid-configuration
GET https://login.microsoftonline.com/common/discovery/v2.0/keys
```

Valid tenants return metadata, invalid return 404.

### User Enumeration
- `https://login.microsoftonline.com/<tenant>/GetCredentialType` — reveals if email exists
- Login UX: "Your organization..." vs "No account found" messages

## Attack Vectors

### Password Spray
Low-and-slow: 1-3 passwords per user per 24h. Use common patterns: `Winter2024!`, `Spring2025!`, `P@ssw0rd`.
Target: federated users (non-federated may have MFA enforcement).

### MFA Bypass Techniques
- **Legacy auth:** Enable IMAP/POP/SMTP auth — not MFA-protected on many tenants
- **App passwords:** If user created app password before MFA enforcement, app passwords bypass MFA
- **Conditional access policies:** Check for legacy auth protocols excluded from CA policies
- **Device code phishing:** Trick user into authenticating on attacker-controlled device

### OAuth App Permissions Abuse
- User-consented OAuth apps with `openid`, `profile`, `email`, `offline_access`
- Admin-consented apps with `Mail.Read`, `Files.ReadWrite.All`, `User.Read.All`
- Test: find OAuth apps in tenant with excessive permissions

### Token Replay / PRT Theft
- Primary Refresh Token (PRT) in Windows: extracted from `%LOCALAPPDATA%\Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\AC\TokenBroker\Accounts`
- PRT + session key → authenticate as any device user
- Token replay: capture PRT, use on attacker machine

### Device Code Phishing
```
https://microsoft.com/devicelogin  → device code → victim enters code → attacker gets token
```

## Confirmation Gates
- Valid user enumeration → informational (but useful for password spray)
- Password spray success → confirmed + high (first step to broader access)
- MFA bypass via legacy auth → confirmed + critical
- OAuth app with excessive permissions → confirmed + high
- PRT theft → confirmed + critical

## Chain Templates
- Password spray + Legacy auth → mailbox access without MFA
- OAuth app abuse + Mail.Read → read all user emails → account recovery → ATO
- Device code phish + PRT theft → persistent access without password
