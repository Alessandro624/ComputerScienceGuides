# Cloud Misconfigurations

## Scopo

Questa guida copre le misconfigurazioni più comuni in ambienti cloud (AWS, Azure, GCP) che portano a vulnerabilità di sicurezza, con tecniche di identificazione e remediation.

## Prerequisiti

- Accesso all'ambiente cloud
- CLI cloud configurate
- ScoutSuite, Prowler o simili
- **Autorizzazione per testing**

---

## Storage Pubblico

### AWS S3

```bash
# Test accesso pubblico
aws s3 ls s3://bucket-name --no-sign-request

# ACL check
aws s3api get-bucket-acl --bucket bucket-name

# Policy check
aws s3api get-bucket-policy --bucket bucket-name

# Public access block
aws s3api get-public-access-block --bucket bucket-name
```

#### Problemi Comuni

```
- PublicRead/PublicReadWrite ACL
- Bucket policy con Principal: "*"
- Public Access Block disabilitato
- Static website hosting con dati sensibili
```

#### Fix

```bash
# Abilita public access block
aws s3api put-public-access-block --bucket BUCKET \
    --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

### Azure Blob

```bash
# Verifica container pubblico
az storage container show-permission --name CONTAINER --account-name ACCOUNT

# Lista pubblicamente
curl "https://ACCOUNT.blob.core.windows.net/CONTAINER?restype=container&comp=list"
```

### GCP Storage

```bash
# IAM policy
gsutil iam get gs://BUCKET

# Pubblico?
curl "https://storage.googleapis.com/BUCKET"

# AllUsers o AllAuthenticatedUsers = pubblico
```

---

## IAM Misconfigurations

### AWS

```bash
# Policies troppo permissive
aws iam list-policies --scope Local
aws iam get-policy-version --policy-arn ARN --version-id v1

# Wildcards pericolosi
# "Action": "*"
# "Resource": "*"

# Access keys vecchie
aws iam list-access-keys --user-name USER
aws iam get-access-key-last-used --access-key-id KEY_ID
```

### Azure

```bash
# Role assignments
az role assignment list --all

# Ruoli custom troppo permissivi
az role definition list --custom-role-only

# Troppi Global Admins
az ad directory-role list
```

### GCP

```bash
# IAM bindings
gcloud projects get-iam-policy PROJECT_ID

# Primitive roles (evitare)
# roles/owner, roles/editor, roles/viewer

# Service account keys
gcloud iam service-accounts keys list --iam-account SA@PROJECT.iam.gserviceaccount.com
```

---

## Network Security

### AWS Security Groups

```bash
# Regole troppo aperte
aws ec2 describe-security-groups --query "SecurityGroups[*].{ID:GroupId,Ingress:IpPermissions}"

# 0.0.0.0/0 su porte sensibili
# SSH (22), RDP (3389), DB ports
```

### Azure NSG

```bash
# Network Security Groups
az network nsg list
az network nsg rule list --nsg-name NSG --resource-group RG

# Porte aperte a Internet
```

### GCP Firewall

```bash
# Firewall rules
gcloud compute firewall-rules list

# Source 0.0.0.0/0 su porte sensibili
gcloud compute firewall-rules describe RULE_NAME
```

---

## Encryption Issues

### Storage

```bash
# AWS S3 encryption
aws s3api get-bucket-encryption --bucket BUCKET

# Azure Storage encryption
az storage account show --name ACCOUNT --query "encryption"

# GCP default encryption (sempre on)
# Ma verifica CMEK
```

### Database

```bash
# AWS RDS
aws rds describe-db-instances --query "DBInstances[*].{ID:DBInstanceIdentifier,Encrypted:StorageEncrypted}"

# Azure SQL
az sql db show --name DB --server SERVER --resource-group RG --query "transparentDataEncryption"
```

### In Transit

```
- TLS/SSL abilitato
- Certificate validi
- Versioni TLS moderne (1.2+)
```

---

## Logging e Monitoring

### AWS CloudTrail

```bash
# Trail attivo?
aws cloudtrail describe-trails
aws cloudtrail get-trail-status --name TRAIL_NAME

# Log file validation
# Multi-region?
```

### AWS Config

```bash
# Recorder attivo?
aws configservice describe-configuration-recorders
aws configservice describe-delivery-channels
```

### Azure

```bash
# Activity logs
az monitor activity-log list

# Diagnostic settings
az monitor diagnostic-settings list --resource RESOURCE_ID
```

### GCP

```bash
# Audit logs
gcloud logging sinks list

# Cloud Audit Logs abilitati?
gcloud projects get-iam-policy PROJECT_ID --format=json | jq '.auditConfigs'
```

---

## Secrets Management

### Hardcoded Secrets

```bash
# In Lambda/Functions
aws lambda get-function --function-name FUNC --query "Configuration.Environment"

# In EC2 user-data
aws ec2 describe-instance-attribute --instance-id ID --attribute userData

# In container definitions
aws ecs describe-task-definition --task-definition TASK
```

### Fix

```
AWS: Secrets Manager, SSM Parameter Store
Azure: Key Vault
GCP: Secret Manager

Mai env vars per secrets sensibili!
```

---

## Compute Misconfigs

### IMDSv1

```bash
# Verifica IMDS
aws ec2 describe-instances --query "Reservations[*].Instances[*].{ID:InstanceId,IMDS:MetadataOptions}"

# IMDSv1 = HttpTokens: optional (vulnerabile)
```

### Public IPs

```bash
# Istanze con IP pubblico
aws ec2 describe-instances --query "Reservations[*].Instances[*].{ID:InstanceId,PublicIP:PublicIpAddress}"
```

### SSH Keys

```bash
# GCP project-wide SSH keys
gcloud compute project-info describe --format="value(commonInstanceMetadata.items[ssh-keys])"
```

---

## Serverless Security

### Lambda

```bash
# Ruoli troppo permissivi
aws lambda list-functions --query "Functions[*].{Name:FunctionName,Role:Role}"

# VPC configuration
aws lambda get-function --function-name FUNC --query "Configuration.VpcConfig"
```

### API Gateway

```bash
# Autenticazione mancante
aws apigateway get-rest-apis
aws apigateway get-method --rest-api-id ID --resource-id RES --http-method GET
```

---

## Tools

### ScoutSuite

```bash
pip install scoutsuite

# AWS
scout aws

# Azure  
scout azure --cli

# GCP
scout gcp --service-account key.json

# Report HTML generato
```

### Prowler (AWS)

```bash
pip install prowler

# Tutti i check
prowler

# Categoria specifica
prowler -g forensics-ready
prowler -c check11,check12
```

### CloudSploit

```bash
git clone https://github.com/aquasecurity/cloudsploit.git
cd cloudsploit
npm install
./index.js --cloud aws --config config.js
```

### Checkov (IaC)

```bash
pip install checkov

# Terraform
checkov -d /path/to/terraform

# CloudFormation
checkov -f template.yaml
```

---

## Mitigazioni

### Governance

```
- Cloud Security Posture Management (CSPM)
- Policy as Code
- Automated remediation
- Regular audits
```

### AWS

```
- AWS Config rules
- Security Hub
- GuardDuty
- Access Analyzer
```

### Azure

```
- Microsoft Defender for Cloud
- Azure Policy
- Azure Security Center
```

### GCP

```
- Security Command Center
- Organization policies
- Asset Inventory
```

---

## Best Practices

- **Automated scanning**: CI/CD integration
- **Baseline**: Definisci configurazioni sicure
- **Least privilege**: Sempre minimo necessario
- **Encryption**: At rest e in transit
- **Monitoring**: Logging completo

## Riferimenti

- [AWS Security Best Practices](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/)
- [Azure Security Best Practices](https://docs.microsoft.com/azure/security/fundamentals/best-practices-and-patterns)
- [GCP Security Best Practices](https://cloud.google.com/security/best-practices)
- [CIS Benchmarks](https://www.cisecurity.org/benchmark/)
