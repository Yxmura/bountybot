---
name: osint-methodology
description: "Open Source Intelligence (OSINT) methodology for bug bounty and external red-team. Domain enumeration, subdomain discovery, certificate transparency, email/employee enumeration, GitHub dorking, technology stack fingerprinting, cloud storage discovery. Use during the recon phase before active testing."
---

# OSINT Methodology

## Domain & Subdomain Enumeration

```
subfinder -d target.com -all -silent
```
Also query:
- crt.sh: `https://crt.sh/?q=%25.target.com`
- Certificate Transparency logs: `https://search.censys.io/certificates?q=target.com`
- DNS brute-force: common subdomain wordlists (SecLists, Assetnote)
- DNS records: MX, TXT, NS, CNAME for target domain

## Technology Fingerprinting

```
whatweb -a 3 target.com
httpx -l hosts.txt -sc -ct -title -server -td -json
```

Check:
- Wappalyzer (browser extension)
- BuiltWith (API)
- WAF detection: `wafw00f target.com`

## Email & Employee Enumeration

- LinkedIn search: `site:linkedin.com/in "target company"`
- `https://haveibeenpwned.com/DomainSearch`
- Email format: `john.doe@target.com` → verify via email verification APIs
- Google dork: `site:target.com "@target.com"`

## GitHub Dorking

```
org:target.com password
org:target.com api_key
org:target.com SECRET_KEY
org:target.com .env
org:target.com aws_access_key
org:target.com --password
org:target.com npmrc
org:target.com .npmrc _auth
```

## Cloud Storage Discovery

- `https://target.s3.amazonaws.com` — public bucket?
- `https://target.s3.us-east-1.amazonaws.com` — regional bucket?
- `https://storage.googleapis.com/target-bucket`
- Grayhat Warfare: `https://buckets.grayhatwarfare.com/`

## Google Dork Patterns

Discovered during OSINT phase can surface:
```
site:target.com intitle:"index of" / parent directory
site:target.com inurl:/.env
site:target.com filetype:sql / SQL dump
site:target.com filetype:pdf confidential
site:target.com inurl:wp-content/uploads
```

## Tools Used in This Phase
```
subfinder, httpx, whatweb, naabu, katana, unfurl, shodan, amass, gau
secret_scanner extension → scan found JS for credentials
```
