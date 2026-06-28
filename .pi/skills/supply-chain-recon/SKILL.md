---
name: supply-chain-recon
description: "Supply chain reconnaissance for third-party dependency attack surface. JavaScript package detection (npm, yarn), CDN/library discovery, subdomain takeover potential, S3 bucket recon in third-party JS, service worker audit, dependency version scanning. Use during recon on JS-heavy web applications."
---

# Supply Chain Recon

## JavaScript Dependency Detection

### Manual Review
```
In JS bundles, search for:
- import { ... } from "package-name"
- require("package-name")
- https://cdn.example.com/libs/package/version/
- CDN URL patterns: cdnjs, unpkg, jsdelivr, skypack
```

### CDN Library Detection
- `https://cdnjs.cloudflare.com/ajax/libs/library/X.Y.Z/library.min.js`
- `https://unpkg.com/library@X.Y.Z/dist/library.js`
- `https://cdn.jsdelivr.net/npm/library@X.Y.Z/dist/library.min.js`
- `//ajax.googleapis.com/ajax/libs/library/X.Y.Z/library.min.js`

## Subdomain Takeover Potential

### Unclaimed CDN / Cloud Resources
Scan acquired hosts:
```
nslookup dead-host.target.com  → NXDOMAIN
```
Then check if service provider has a "claim this resource" flow:
- AWS S3: no such bucket
- Heroku: no such app
- GitHub Pages: 404
- Azure: missing resource
- Shopify: no store found

If DNS CNAME points to resource that is no longer claimed → subdomain takeover.

### Common Takeover Patterns
```
CNAME: target.s3.amazonaws.com (unclaimed)
CNAME: target.herokuapp.com (deleted)
CNAME: target.github.io (repo deleted)
CNAME: target.netlify.app (site deleted)
CNAME: target.trafficmanager.net (unclaimed)
```

## Third-Party Data Flows

### Cross-Domain Data Transmission
From JS analysis, identify where data is sent:
- Analytics: Google Analytics, Mixpanel, Heap, Segment
- Monitoring: Sentry, Datadog, New Relic, LogRocket
- Third-party: Stripe, PayPal, Plaid, Auth0

### Service Worker Audit
```
/sw.js
navigator.serviceWorker.register('/sw.js')
```
Service workers intercept all requests for their scope. If service worker is malicious or misconfigured → full request interception.

## Confirmation Gates
- CDN script loading from unmaintained package → provisional (supply chain risk)
- Subdomain takeover confirmed (DNS + service provider → claimable) → confirmed + high
- Service worker with broad interception → confirmed + high

## Chain Templates
- Subdomain takeover + OAuth → token theft on auth subdomain
- Supply chain dependency + CDN → serve malicious JS via compromised CDN library
- Service worker + Stored XSS → persistent XSS via worker cache
