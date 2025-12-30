# Cloud Security Tools

## Scopo

Questa guida copre tool per auditing, assessment e penetration testing di ambienti cloud (AWS, Azure, GCP) e relative infrastrutture.

## Prerequisiti

- Account cloud con credenziali
- CLI cloud installate
- Conoscenza IAM e servizi cloud
- **Autorizzazione per testing**

---

## Multi-Cloud

### ScoutSuite

```bash
# Installazione
pip install scoutsuite

# AWS
scout aws

# Azure
scout azure --cli

# GCP
scout gcp --service-account credentials.json

# Report
# Genera report HTML in scout-report/
```

### CloudSploit

```bash
# Installazione
git clone https://github.com/aquasecurity/cloudsploit.git
cd cloudsploit
npm install

# Config
cp config_example.js config.js
# Edit with credentials

# Run
node index.js
```

### Steampipe

```bash
# Installazione
brew install turbot/tap/steampipe

# Plugin AWS
steampipe plugin install aws

# Query
steampipe query "select * from aws_s3_bucket where versioning_enabled = false"

# Dashboard
steampipe dashboard
```

---

## AWS

### AWS CLI

```bash
# Configurazione
aws configure

# Verifica identità
aws sts get-caller-identity

# Enumeration
aws s3 ls
aws iam list-users
aws ec2 describe-instances
aws lambda list-functions
```

### Prowler

```bash
# Installazione
pip install prowler

# Run completo
prowler aws

# Checks specifici
prowler aws -c check11 -c check12

# Output
prowler aws -M json-ocsf -o prowler-output
```

### Pacu

```bash
# Installazione
git clone https://github.com/RhinoSecurityLabs/pacu.git
cd pacu
pip install -r requirements.txt

# Avvio
python3 pacu.py

# Comandi
Pacu > import_keys --all
Pacu > run iam__enum_permissions
Pacu > run iam__privesc_scan
Pacu > run ec2__enum
Pacu > run lambda__enum
```

### Enumerate IAM

```bash
# enumerate-iam
python enumerate-iam.py --access-key AKIA... --secret-key SECRET

# Policies
aws iam list-attached-user-policies --user-name USERNAME
aws iam get-policy --policy-arn ARN
aws iam get-policy-version --policy-arn ARN --version-id v1
```

### S3 Tools

```bash
# s3scanner
s3scanner scan --bucket bucket-name

# S3 enum
aws s3 ls s3://bucket --no-sign-request
aws s3 cp s3://bucket/file.txt . --no-sign-request

# bucket_finder
bucket_finder.rb wordlist.txt
```

### CloudMapper

```bash
# Installazione
git clone https://github.com/duo-labs/cloudmapper.git
cd cloudmapper
pip install -r requirements.txt

# Collect
python cloudmapper.py collect --account my_account

# Visualize
python cloudmapper.py prepare --account my_account
python cloudmapper.py webserver
```

---

## Azure

### Azure CLI

```bash
# Login
az login

# Account info
az account show
az account list

# Enumeration
az vm list
az storage account list
az ad user list
az keyvault list
```

### AzureHound

```bash
# Collect data per BloodHound
./azurehound -c All

# Con refresh token
./azurehound -r REFRESH_TOKEN -c All

# Import in BloodHound
# Upload JSON files
```

### ROADtools

```bash
# Installazione
pip install roadrecon roadtx

# Auth
roadtx auth -u user@domain.com -p password

# Dump
roadrecon dump

# GUI
roadrecon gui
# http://127.0.0.1:5000
```

### MicroBurst

```powershell
# Import
Import-Module .\MicroBurst.psm1

# Enumeration
Invoke-EnumerateAzureBlobs -Base company
Invoke-EnumerateAzureSubDomains -Base company
Get-AzurePasswords

# Storage
Get-StorageAccountsFromCert
```

### PowerZure

```powershell
# Import
ipmo .\PowerZure.ps1

# Enumeration
Get-AzureADUsers
Get-AzureRoleAssignment
Get-AzureRunAsAccounts

# Exploitation
New-AzureUser -Username backdoor
```

---

## GCP

### gcloud CLI

```bash
# Auth
gcloud auth login
gcloud auth application-default login

# Info
gcloud config list
gcloud projects list

# IAM
gcloud iam service-accounts list
gcloud projects get-iam-policy PROJECT_ID
```

### GCP Scanner

```bash
# gcp_scanner
python3 gcp_scanner.py -o output.json

# Specifico progetto
python3 gcp_scanner.py -p PROJECT_ID
```

### GCPBucketBrute

```bash
# Bucket enumeration
python3 gcpbucketbrute.py -k keywords.txt -s

# Con wordlist
python3 gcpbucketbrute.py -w wordlist.txt
```

---

## Kubernetes

### kubectl

```bash
# Get pods
kubectl get pods --all-namespaces

# Secrets
kubectl get secrets --all-namespaces
kubectl get secret SECRET -o jsonpath='{.data}'

# RBAC
kubectl auth can-i --list
kubectl auth can-i create pods
```

### kube-hunter

```bash
# Remote
kube-hunter --remote TARGET_IP

# Pod mode
kube-hunter --pod

# Active mode
kube-hunter --remote TARGET_IP --active
```

### kube-bench

```bash
# CIS benchmark
kube-bench run --targets master
kube-bench run --targets node
```

### Kubeaudit

```bash
# All checks
kubeaudit all

# Specific
kubeaudit privileged
kubeaudit nonroot
kubeaudit rootfs
```

---

## Container

### Trivy

```bash
# Scan image
trivy image nginx:latest

# Filesystem
trivy fs /path

# IaC
trivy config ./terraform

# Severity filter
trivy image --severity HIGH,CRITICAL nginx
```

### Grype

```bash
# Scan
grype nginx:latest

# SBOM
syft nginx:latest -o json | grype
```

### Docker Bench

```bash
# Security audit
docker run --rm --net host --pid host --userns host --cap-add audit_control \
    -e DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST \
    -v /etc:/etc:ro \
    -v /var/lib:/var/lib:ro \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    docker/docker-bench-security
```

---

## Infrastructure as Code

### Checkov

```bash
# Terraform
checkov -d /path/to/terraform

# CloudFormation
checkov -f template.yaml

# Kubernetes
checkov -f deployment.yaml
```

### tfsec

```bash
# Scan
tfsec .

# Severity
tfsec --minimum-severity HIGH
```

### KICS

```bash
# Scan
kics scan -p /path

# Multiple platforms
kics scan -p . -t Terraform,CloudFormation,Kubernetes
```

---

## Credential Tools

### TruffleHog

```bash
# Git repo
trufflehog git https://github.com/repo.git

# Filesystem
trufflehog filesystem /path

# S3
trufflehog s3 --bucket bucket-name
```

### GitLeaks

```bash
# Scan repo
gitleaks detect --source /path/to/repo

# Pre-commit
gitleaks protect --staged
```

---

## Best Practices

- **Least privilege**: Cred minime necessarie
- **Logging**: Abilita CloudTrail/Audit
- **Scope**: Rispetta boundaries
- **Cleanup**: Rimuovi risorse test
- **Reports**: Documenta findings

## Riferimenti

- [ScoutSuite](https://github.com/nccgroup/ScoutSuite)
- [Prowler](https://github.com/prowler-cloud/prowler)
- [Pacu](https://github.com/RhinoSecurityLabs/pacu)
- [Cloud Security Alliance](https://cloudsecurityalliance.org/)
