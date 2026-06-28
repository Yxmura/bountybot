---
name: enterprise-vpn
description: "Enterprise security testing skill for SSL VPN appliances. Cisco ASA/Firepower, Fortinet FortiGate, Citrix NetScaler (ADC), Palo Alto GlobalProtect, Pulse Secure (Ivanti), SonicWall, F5 BIG-IP. Detection patterns, CVE chains, auth bypass, post-credential escalation, session hijacking, patching posture assessment."
---

# Enterprise: SSL VPN Appliance Attacks

## Detection & Fingerprinting

| Vendor | Port(s) | Fingerprint |
|---|---|---|
| **Cisco ASA/Firepower** | 443, 8443 | `/onep`, `/admin/login`, `/netaccess` |
| **Fortinet FortiGate** | 443, 10443 | `/remote/login`, `/login`, `X-Fortinet-*` headers |
| **Citrix NetScaler/ADC** | 443, 8443 | `/gwtest/`, `/vpn/index.html`, `/logon/LogonPoint/` |
| **Palo Alto GlobalProtect** | 443, 5007 | `/global-protect/login.esp`, `/sslmgr` |
| **Pulse Secure/Ivanti** | 443, 8443 | `/dana-na/auth/url_admin/login.cgi`, `/dana-na/nc/` |
| **SonicWall SMA/SSLVPN** | 443, 8443 | `/cgi-bin/login`, `/sonicui` |
| **F5 BIG-IP** | 443, 8443 | `/tmui/login`, `/my.policy`, `/xui/` |

## CVE Chain Targeting

### Citrix NetScaler (frequent targets)
- **CVE-2023-3519:** RCE in NetScaler ADC/Gateway 12.1/13.0/13.1 before certain builds. Unauthenticated do not require the ICA connection.
- **CVE-2024-8060:** SAML auth bypass in NetScaler ADC. Pre-auth session hijack.
- **CVE-2022-27518:** RCE in NetScaler SAML component.
- Test: check /gwtest/, /logon/, /vpn/ for version or known-exploitable pages.

### Fortinet FortiGate
- **CVE-2023-27997:** Heap buffer overflow in FortiOS/Proxy IPsec → unauthenticated RCE.
- **CVE-2024-21762:** FortiOS FG-IR-23-432, authentication bypass in admin interface.
- Test: check `/remote/login` for pre-patched FortiOS version.

### Cisco ASA
- **CVE-2024-20402:** RCE in Cisco ASA/FTD SSL VPN.
- **CVE-2023-20073:** VPN VPN (CVE-2023-20073) RCE in Cisco ASA/FTD webVPN.
- Test: check `/onep`, `/netaccess` for version disclosure.

### Ivanti Pulse Secure
- **CVE-2023-46805 / CVE-2024-21887:** Auth bypass + RCE chain (wildly exploited 2024).
- Test: `/dana-na/auth/` presence + version header → vulnerable builds.

## Post-Credential Escalation

### Citrix NetScaler
- Extract `/nsconfig/ns.conf` — contains VPN config, shared keys, user entries
- NetScaler SAML signing keys → forge SAML tokens
- Extract session cookies from `/tmp/` session tracking

### Fortinet FortiGate
- Extract `/etc/config.conf` — full config incl. VPN secrets, LDAP bind creds
- `fnsysctl` command: can run commands from WebUI
- FortiManager inter-appliance trust → lateral to FMG

### Pulse Secure/Ivanti
- Extract `/data/config/store` — stored configuration with credentials
- Session cookie replay: captured `DSID` cookie → authenticate from another IP
- `PS_*` cookies → session hijacking

## Patching Posture Assessment
- 3+ years without a security update → will have multiple CVEs
- Exposed management interface (not just VPN portal) → direct attack surface
- End-of-life versions: ASA 9.12-, FortiOS 6.4-, NetScaler 12.1-

## Confirmation Gates
- VPN portal accessible → informational (if in scope)
- Version string includes known CVE → provisional (check exact build)
- CVE PoC works → confirmed (high to critical)
- Auth bypass → confirmed + critical
- Config extraction with credentials → confirmed + critical

## Chain Templates
- VPN auth bypass + SSRF → pivot through VPN appliance to internal network
- VPN CVE + Config extraction → extract LDAP/PKI credentials → domain pivot
- Session cookie hijack + IDOR → access user-specific VPN portal data
- VPN RCE + Cloud Metadata → IAM credentials from cloud provider
