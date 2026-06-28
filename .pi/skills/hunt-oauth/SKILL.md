---
name: hunt-oauth
description: "Hunting skill for OAuth 2.0 and OIDC vulnerabilities. redirect_uri bypass, CSRF via state parameter, PKCE enforcement, implicit flow token leakage, client_secret exposure, authorization code interception. Use when testing OAuth/OIDC authentication flows."
---

# Hunt: OAuth 2.0 / OIDC

## OAuth Flow Components
```
Provider (Auth0, Okta, Google, Facebook, custom)
  ↕ authorization code / token
Client (the target application)
  ↕ redirect_uri
User (browser)
```

## Attack Vectors

### redirect_uri Bypass
```
redirect_uri=https://target.com/callback
→ redirect_uri=https://target.com/callback.evil.com
→ redirect_uri=https://target.com/callback?continue=https://evil.com
→ redirect_uri=https://target.com/callback#https://evil.com
→ redirect_uri=https://evil.com
→ redirect_uri=null
```
If OAuth provider accepts attacker-controlled redirect_uri → steal auth code.

### State Parameter Missing/Weak
```
/auth?response_type=code&client_id=xxxx&redirect_uri=...
```
If state param is missing or predictable → CSRF attack on OAuth flow. Attacker initiates auth, victim completes it, attacker uses victim's authorization.

### PKCE Not Enforced
```
code_challenge=...  (should be required for public clients)
```
If PKCE is missing but server still accepts code without it → code interception attack.

### Implicit Flow (response_type=token)
```
/auth?response_type=token&client_id=xxxx&redirect_uri=...
```
Access token in URL fragment → leaked to:
- Referer header on subsequent requests
- Browser history
- Any script running on the page

### Client Secret Exposure
```
Search JS bundles for: client_secret, CLIENT_SECRET, clientId, client-id
```
Exposed client secret + accepted redirect_uri URL → full OAuth abuse.

### Authorization Code Interception
If code is returned in URL params:
- Check if code is exchanged by server without client_secret validation
- Try replaying code
- Try using code from one client on another client

## Confirmation Gates
- Accepts attacker redirect_uri → ATO via token theft
- Missing state → CSRF in OAuth flow
- Token in URL fragment (implicit) → token leak confirmed
- Client secret in JS → credential exposure confirmed

## Chain Templates
- OAuth redirect_uri + Open Redirect → steal auth code via open redirect
- OAuth + State missing + XSS → state parameter CSRF + XSS = ATO
- Implicit flow + Referer leak → token in Referer header
- Client secret leak + SSRF → use secret to authorize on provider
