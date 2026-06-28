---
name: hunt-idor
description: "Hunting skill for Insecure Direct Object Reference (IDOR) vulnerabilities. Detection patterns, UUID enumeration, parameter tampering, mass assignment, horizontal and vertical privilege escalation. Use when testing any endpoint referencing user IDs, object IDs, or resource identifiers."
---

# Hunt: IDOR (Insecure Direct Object Reference)

## Detection Patterns

### Numeric ID Enumeration
```
GET /api/users/1
GET /api/users/2
GET /api/users/3
```
Test: change the ID and see if you get another user's data.

### UUID Enumeration
```
GET /api/orders/550e8400-e29b-41d4-a716-446655440000
GET /api/orders/550e8400-e29b-41d4-a716-446655440001
```
Test: if UUIDs are guessable (sequential, timestamp-based), enumerate.

### Parameter Tampering
```
POST /api/transfer
{"from": "my-account", "to": "attacker-account", "amount": 100}

→ {"from": "victim-account", "to": "attacker-account", "amount": 100}
```

### Mass Assignment
```
PATCH /api/users/me
{"email": "new@email.com", "role": "admin"}
```
Test: add unexpected fields like `role`, `isAdmin`, `permissions`.

### Indirect Reference
```
GET /download?file_id=123
```
Test: change file_id to get another user's documents.

## Detection Methodology

1. Create two accounts (User A and User B)
2. Perform authenticated action as User A
3. Extract the object reference parameter (ID, UUID, hash)
4. Switch to User B session
5. Try to access User A's object reference
6. If you can see User A's data → IDOR confirmed

## Common Vulnerable Endpoints

```
GET /api/users/<id>
GET /api/orders/<id>
GET /api/invoices/<id>
GET /api/documents/<id>
GET /api/messages/<id>
GET /api/profile/<id>
GET /api/account/<id>/transactions
POST /api/transfer
PATCH /api/users/<id>
DELETE /api/users/<id>
```

## Horizontal vs Vertical IDOR

**Horizontal IDOR:** User A can modify/read User B's data of the same privilege level.
- Test: change user_id parameter to another user's ID
- Severity: Medium to High depending on data sensitivity

**Vertical IDOR (Privilege Escalation):** User can perform admin actions.
- Test: access /api/admin/* endpoints as regular user
- Test: add `role=admin` to PATCH/POST body
- Severity: High to Critical

## Bypass Techniques

| Protection | Bypass |
|---|---|
| GUID/UUID | If sequential (UUID v1, timestamp-based), enumerate |
| Hash IDs | Decode hash, check if reversible |
| JWT contains user ID | Decode JWT, check if you can edit it |
| Server-side role check | Try array of user IDs, mass assignment |
| Rate limit on enumeration | Use slow enumeration, proxy rotation |
| Object-level check present | Check if it prevents HORIZONTAL but allows VERTICAL (or vice versa) |

## Confirmation Gates
- Can read another user's private data (email, address, orders) → confirmed
- Can modify another user's data → confirmed
- Can perform admin actions as user → confirmed
- UUID returns 200 but content doesn't show other user's data → not confirmed

## Chain Templates
- IDOR + User ID enumeration → mass PII exfiltration
- IDOR + Business Logic → privilege escalation via parameter tampering
- IDOR + CSRF → force state change on another user
- IDOR + Password Reset → account takeover via IDOR in reset flow
