---
name: enterprise-vcenter
description: "Enterprise security testing skill for VMware vCenter and Workspace ONE. vCenter CVE chains (2024-2026), post-credential escalation in vSphere, vCenter SSO bypass, VCSA SSH key reuse, ESXi host takeover. Use when testing VMware vCenter/ESXi infrastructure."
---

# Enterprise: VMware vCenter / Workspace ONE

## vCenter CVE Chains

### CVE-2024-38812 (vCenter RCE)
Vulnerability in DCERPC protocol. Unauthenticated RCE in vCenter Server 7.0/8.0.
Test: send crafted DCERPC request to port 2012/TCP (vCenter DCERPC endpoint).

### CVE-2024-37079 (vCenter heap overflow)
Heap overflow in DCERPC implementation. Results in RCE on vCenter appliance.

### CVE-2023-34048 (vCenter out-of-bounds write)
vCenter DCERPC protocol out-of-bounds write. Unauthenticated RCE.

### CVE-2022-22972 (vCenter auth bypass)
VMware Workspace ONE Access, Identity Manager, and vRealize automation auth bypass.
Test: access endpoints without valid authentication token.

## Post-Credential Escalation

### VCSA SSH Key Reuse
vCenter Server Appliance (VCSA) uses the same SSH key across installs.
Known keys for specific versions → authenticate to any VCSA with root access.

### vCenter SSO Bypass
If you have admin on vCenter → extract SSO domain credentials.
Use `sts-admin` or `dir-cli` on VCSA to enumerate and forge SSO tokens.

### ESXi Host Takeover
From vCenter admin → push VIB (vSphere Installation Bundle) to ESXi hosts.
VIB with backdoor → full ESXi host compromise.

## Confirmation Gates
- vCenter accessible on port 443/2012 → could be vulnerable
- CVE-2024-38812 hits confirmed RCE → critical
- VCSA SSH key reuse works → high
- SSO credentials extracted → critical

## Chain Templates
- vCenter RCE + Cloud Metadata → IAM from underlying vSAN/VMFS host
- vCenter SSO + Workspace ONE → cross-application authentication → broader access
- ESXi VIB + VM escape → hypervisor host compromise
