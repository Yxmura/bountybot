---
name: enterprise-sharepoint
description: "Enterprise security testing skill for Microsoft SharePoint (on-premises and SharePoint Online). NTLM relay, SOAP endpoints legacy abuse, ToolShell access, SharePoint workflow abuse, privilege escalation in SharePoint, cross-site data access. Use when testing SharePoint deployment."
---

# Enterprise: Microsoft SharePoint Security Testing

## Reconnaissance

### Version Detection
```
GET /_layouts/15/settings.aspx
GET /_vti_pvt/service.cnfg
GET /_vti_inf.html
```
SharePoint on-prem can be identified via:
- `/_layouts/` paths indicating version (15=2013, 16=2016/2019/SE)
- `MicrosoftSharePointTeamServices` header
- `X-SharePointHealthScore` header

### Endpoint Discovery
```
/_api/web/
/_api/web/lists
/_api/web/sitegroups
/_vti_bin/
/_vti_bin/search.asmx
/_vti_bin/lists.asmx
/_vti_bin/userprofileservice.asmx
/_vti_bin/webservice.asmx
/_vti_bin/cellstorageservice.asmx
```

## Attack Vectors

### NTLM Relay / Credential Harvesting
SharePoint on-prem has NTLM-authenticated endpoints. Use the TOOLSHELL methodology:
- Capture NTLM hash via SMB share access or `Responder`
- Relay NTLM to SharePoint endpoints for authenticated access
- Legacy SOAP webservices (`/_vti_bin/*.asmx`) often accept NTLM without additional auth

### ToolShell Access
ToolShell is a PowerShell module for SharePoint management. If accessible:
- `Get-SPWebApplication` — list all web apps
- `Get-SPSite` — list all site collections
- `Get-SPUser` — enumerate users with permissions
- WebDAV access for file read/write

### SharePoint Online (M365)
- SharePoint Online typically behind M365 auth → use M365 attack vectors
- Check for external sharing enabled on sensitive docs
- Check for anonymous access token in links (guest access)
- CSOM (Client-Side Object Model) access with compromised tokens

### Legacy SOAP Abuse
SharePoint 2013-2019 have legacy SOAP webservices:
```
/_vti_bin/Lists.asmx?op=GetListItems  — read list items without auth in some configurations
/_vti_bin/UserProfileService.asmx     — user profile enumeration
/_vti_bin/Search.asmx                 — search across sites (may include restricted content)
```

### Workflow Abuse
SharePoint workflows can trigger:
- Approval chain bypass
- Document routing to unauthorized locations
- Impersonation during workflow execution

## Confirmation Gates
- SharePoint endpoint exposed → informational
- NTLM challenge received → credential harvesting opportunity
- Legacy SOAP returns data without auth → confirmed + high
- ToolShell access → confirmed + critical
- External sharing enabled on sensitive data → confirmed + high

## Chain Templates
- SharePoint NTLM + Legacy SOAP → read all SharePoint data without auth
- SharePoint + M365/Entra → pivot from SharePoint access to M365 mail/teams
- SharePoint Workflow + Privilege Escalation → admin access via workflow abuse
