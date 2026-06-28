---
name: enterprise-cloud-iam
description: "Enterprise cloud IAM security testing skill. AWS IAM role chaining, STS AssumeRole abuse, cross-account trust, GCP service account impersonation, Azure managed identity abuse. Use when testing cloud infrastructure or following up on discovered cloud credentials."
---

# Enterprise: Cloud IAM Security Testing

## AWS IAM

### Role Chaining
```
Discovered AWS Access Key → sts:AssumeRole on higher-privlege role
```
Check: does discovered key have `sts:AssumeRole` permission? If yes → chain to admin role.

### Cross-Account Trust Abuse
```
Check AWS resource policies for Principal: "*" or Principal: "arn:aws:iam::<other>:*"
```
Cross-account trust allows one AWS account's users to access another account's resources.

### IMDS Credential Abuse
From EC2 with HTTP SSRF:
```
http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
```
Extracted creds can be used from outside the instance.

### S3 Bucket Attack Paths
```
s3:GetObject on bucket with wrong ACL → enumerate bucket
s3:PutObject on bucket → plant malicious content (e.g. JS for downstream users)
s3:ListBucket on account → full inventory
```

## GCP IAM

### Service Account Impersonation
```
gcloud auth print-access-token —impersonate-service-account=<sa>@<project>.iam.gserviceaccount.com
```
If current token can `iam.serviceAccounts.actAs` → gain SA's privileges.

### Cloud IAP Abuse
IAP-protected resources: check if and how access is enforced.
- Check for blanket `IAP-secured Web App User` on all users
- Check for bypass via direct VPC connectivity

## Azure Managed Identity

### MSI Token Abuse
From Azure VM/App Service SSRF:
```
GET http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
Header: Metadata: true
```
Extracted token → authenticate as managed identity to Azure Resource Manager.

### Storage Account Access
```
az storage blob list --account-name <target>
```
With managed identity token → list all blobs in storage account.

## Confirmation Gates
- IAM credentials from IMDS → confirmed + critical
- sts:AssumeRole success → confirmed + critical
- Service account impersonation success → confirmed + critical
- Azure MSI token extracted → confirmed + critical

## Chain Templates
- AWS IMDS + SSRF → extract IAM credentials → cloud account compromise
- Cross-account trust + ReadWrite permissions → data exfiltration via S3
- GCP SA impersonation + Access Token → G Suite data access
- Azure MSI + Storage → read all app data from storage accounts
