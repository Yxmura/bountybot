---
name: hunt-business-logic
description: "Hunting skill for business logic vulnerabilities. Race conditions, coupon abuse, balance manipulation, rate-limit bypass, 2FA logic flaws, mass assignment, workflow bypass. Use when testing payment, account management, or multi-step business workflows."
---

# Hunt: Business Logic Flaws

## Detection Patterns

### Race Condition
```
POST /coupon/apply
{"code": "FIRST100"}
→ Send same request 50× concurrently
```
If coupon applied multiple times → race condition.

### Balance Manipulation
```
POST /transfer
{"from": "A", "to": "B", "amount": 100}
→ {"from": "A", "to": "B", "amount": -100}
```
Test: negative amounts, decimal amounts, overflow.

### Rate Limit Bypass
```
X-Forwarded-For: 127.0.0.1  (change per request)
X-Forwarded-For: 127.0.0.2
Cookie header removal → different rate-limit bucket
```
### 2FA Logic Flaws
```
- Skip 2FA verification step entirely
- Reuse old 2FA code
- Brute-force 2FA code (4-6 digits, no rate limit)
- Backdoored codes (0000, 111111, 123456)
```

### Workflow Bypass
```
Step 1 → Step 2 → Step 3 (expected)
Step 1 → Step 3 (direct navigation)
```
Test: skip intermediate steps, modify step state parameters.

### Mass Assignment
```
PATCH /api/users
{"email": "new@email.com"}
→ {"email": "new@email.com", "role": "admin", "credits": 9999}
```

## Confirmation Gates
- Coupon applied N× > limit → confirmed + high
- Negative transfer executed → confirmed + high  
- 2FA bypassed → confirmed + high
- Multi-step workflow bypassed → confirmed + medium
- Rate limit bypassed for sensitive action → confirmed + medium

## Chain Templates
- Race condition + Coupon abuse → infinite discount → financial loss
- Mass assignment + IDOR → escalate privileges on another user
- Balance manipulation + Negative amount → drain victim's balance
- 2FA bypass + ATO via credential stuffing → mass account compromise
