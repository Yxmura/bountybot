---
name: hunt-deserialization
description: "Hunting skill for Insecure Deserialization vulnerabilities. PHP deserialization gadget chains, Java deserialization (ysoserial), .NET deserialization, Python pickle deserialization, Node.js deserialization (node-serialize). Use when testing endpoints that accept serialized object data (base64 strings, binary blobs, cookie values)."
---

# Hunt: Insecure Deserialization

## Detection

### PHP Deserialization
```
GET /api/users?data=O:4:"User":1:{s:4:"name";s:5:"admin";}
Cookie: user=Tzo0OiJVc2VyIjoxOntzOjQ6Im5hbWUiO3M6NToiYWRtaW4iO30=
```
Detect: URL/base64-encoded PHP serialized format. `O:4:"User":1:{...}` identifies PHP serialization.

### Java Deserialization
```
Content-Type: application/x-java-serialized-object
POST body: <binary> starting with 0xACED0005
```
Detect: `0xACED0005` (Java serialization magic bytes). Base64 also common.

### .NET Deserialization
```
ViewState: /wEPDwU... (base64)
```
Detect: ViewState or binary formatter serialization.

### Python Pickle
```
Content-Type: application/x-python-serialize
```
Detect: `0x8004` magic bytes. JSON with `__reduce__`, `__reduce_ex__`.

### Node.js node-serialize
```
Cookie: {"rce":"_$$ND_FUNC$$_function(){...}"}
```
Detect: `_$$ND_FUNC$$_` prefix in JSON strings.

## Common Vectors

| Language | Library | Magic Bytes / Format | Tool |
|---|---|---|---|
| PHP | `serialize()`/`unserialize()` | `O:4:"User":1:{...}`, `a:1:{i:0;s:5:"hello"}` | PHPGGC |
| Java | native serialization | `aced0005`, base64 blob | ysoserial |
| Java | JSON (Jackson/Fastjson) | `{"@type":"...","..."`, `$types:{...}` | JNDI/Jdeli |
| .NET | BinaryFormatter | base64 blob, ViewState | ysoserial.net |
| Python | pickle | `0x8004`, `\x80\x04` | picklemagic |
| Node.js | node-serialize | `_$$ND_FUNC$$_` | node-serialize |

## Confirmation Gates
- Serialized data accepted and processed → provisional
- Time delay from deserialization (`Runtime.exec('sleep 5')`) → confirmed
- DNS callback from gadget chain → confirmed + critical
- Class/property manipulation reflected in response → confirmed

## Chain Templates
- Java Deserialization + ysoserial → RCE via gadget chain
- PHP Deserialization + POP Gadgets → SQL injection via framework gadget
- .NET ViewState + MachineKey → forge ViewState with malicious payload → RCE
