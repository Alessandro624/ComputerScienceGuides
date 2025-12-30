# Hardening Guide

## Scopo

Questa guida copre best practices di hardening per sistemi operativi, servizi e applicazioni per migliorare la postura di sicurezza dopo un assessment.

## Prerequisiti

- Accesso amministrativo
- Baseline configuration
- Change management process
- Test environment

---

## Linux Hardening

### User Management

```bash
# Password policy - /etc/login.defs
PASS_MAX_DAYS   90
PASS_MIN_DAYS   7
PASS_MIN_LEN    14
PASS_WARN_AGE   14

# PAM password complexity - /etc/pam.d/common-password
password requisite pam_pwquality.so retry=3 minlen=14 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1

# Disable root login SSH
echo "PermitRootLogin no" >> /etc/ssh/sshd_config

# Remove unused users
userdel username

# Lock account
passwd -l username
```

### SSH Hardening

```bash
# /etc/ssh/sshd_config
Protocol 2
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
PermitEmptyPasswords no
X11Forwarding no
AllowUsers user1 user2
ClientAliveInterval 300
ClientAliveCountMax 2

# Restart
systemctl restart sshd
```

### Firewall (iptables/nftables)

```bash
# Default deny
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow established
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Allow SSH (restrictive)
iptables -A INPUT -p tcp --dport 22 -s TRUSTED_IP -j ACCEPT

# UFW (simpler)
ufw default deny incoming
ufw default allow outgoing
ufw allow from TRUSTED_IP to any port 22
ufw enable
```

### File Permissions

```bash
# Secure home directories
chmod 700 /home/*

# Remove SUID/SGID where not needed
find / -perm /6000 -type f -exec ls -ld {} \;

# Secure sensitive files
chmod 600 /etc/shadow
chmod 644 /etc/passwd
chmod 600 /etc/ssh/sshd_config

# World-writable files
find / -type f -perm -002 -exec ls -l {} \;
```

### System Updates

```bash
# Automatic security updates (Debian/Ubuntu)
apt install unattended-upgrades
dpkg-reconfigure unattended-upgrades

# CentOS/RHEL
yum install yum-cron
systemctl enable yum-cron
```

### Logging

```bash
# Rsyslog configuration
# /etc/rsyslog.conf

# Central log server
*.* @@logserver:514

# Audit daemon
apt install auditd
systemctl enable auditd

# Key audit rules - /etc/audit/rules.d/audit.rules
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /var/log/auth.log -p wa -k auth_log
```

---

## Windows Hardening

### Account Policies

```powershell
# Password policy
net accounts /minpwlen:14 /maxpwage:90 /minpwage:1 /uniquepw:10

# Account lockout
net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30

# Disable Guest
net user Guest /active:no

# Rename Administrator
wmic useraccount where name='Administrator' rename 'CustomAdmin'
```

### Windows Firewall

```powershell
# Enable firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Default deny inbound
Set-NetFirewallProfile -DefaultInboundAction Block

# Block specific ports
New-NetFirewallRule -DisplayName "Block SMB" -Direction Inbound -LocalPort 445 -Protocol TCP -Action Block
```

### Disable Unnecessary Services

```powershell
# List services
Get-Service | Where-Object {$_.StartType -eq "Automatic"}

# Disable
Set-Service -Name "RemoteRegistry" -StartupType Disabled
Set-Service -Name "Telnet" -StartupType Disabled
Stop-Service -Name "RemoteRegistry"
```

### Windows Defender

```powershell
# Enable real-time protection
Set-MpPreference -DisableRealtimeMonitoring $false

# Enable cloud protection
Set-MpPreference -MAPSReporting Advanced

# Update signatures
Update-MpSignature
```

### Audit Policies

```powershell
# Enable auditing
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable
auditpol /set /subcategory:"Account Lockout" /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
```

### SMB Hardening

```powershell
# Disable SMBv1
Set-SmbServerConfiguration -EnableSMB1Protocol $false
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

# Enable SMB signing
Set-SmbServerConfiguration -RequireSecuritySignature $true
```

---

## Network Hardening

### Segmentation

```
- Separate VLAN per funzione
- DMZ per servizi pubblici
- Management network isolata
- Firewall tra segmenti
```

### Switch Security

```
- Port security
- DHCP snooping
- Dynamic ARP inspection
- 802.1X authentication
- Disable unused ports
```

### Router/Firewall

```
- Default deny
- Egress filtering
- Logging abilitato
- Firmware aggiornato
- Disable unused services
```

---

## Web Application Hardening

### Headers

```apache
# Apache
Header always set X-Content-Type-Options "nosniff"
Header always set X-Frame-Options "DENY"
Header always set X-XSS-Protection "1; mode=block"
Header always set Content-Security-Policy "default-src 'self'"
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
```

```nginx
# Nginx
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Content-Security-Policy "default-src 'self'" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

### TLS Configuration

```nginx
# Strong TLS
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
ssl_prefer_server_ciphers on;
ssl_session_cache shared:SSL:10m;
```

### Web Server

```bash
# Hide version
# Apache
ServerTokens Prod
ServerSignature Off

# Nginx
server_tokens off;

# Disable directory listing
# Apache
Options -Indexes

# Nginx
autoindex off;
```

---

## Database Hardening

### MySQL/MariaDB

```sql
-- Remove anonymous users
DELETE FROM mysql.user WHERE User='';

-- Remove remote root
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');

-- Remove test database
DROP DATABASE IF EXISTS test;

-- Flush privileges
FLUSH PRIVILEGES;

-- mysql_secure_installation automatizza
```

### PostgreSQL

```bash
# pg_hba.conf - restrict connections
hostssl all all 10.0.0.0/8 scram-sha-256

# postgresql.conf
ssl = on
password_encryption = scram-sha-256
```

---

## Container Hardening

### Docker

```bash
# Run as non-root
USER nonroot

# Read-only filesystem
docker run --read-only image

# Drop capabilities
docker run --cap-drop ALL --cap-add NET_BIND_SERVICE image

# Resource limits
docker run --memory=512m --cpus=1 image

# Security options
docker run --security-opt=no-new-privileges image
```

### Kubernetes

```yaml
# Pod security context
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop:
      - ALL
```

---

## Tools

| Tool | Uso |
|------|-----|
| Lynis | Linux auditing |
| CIS-CAT | CIS benchmark |
| OpenSCAP | Compliance scanning |
| Microsoft Baseline | Windows hardening |

### Lynis

```bash
# Audit sistema
lynis audit system

# Report
lynis audit system --quick
```

---

## Hardening Checklist

```
[ ] Patch management attivo
[ ] Password policy implementata
[ ] Unnecessary services disabled
[ ] Firewall configurato
[ ] Logging attivo
[ ] Encryption in transit/rest
[ ] Backup verificati
[ ] Antivirus/EDR attivo
[ ] Monitoring configurato
[ ] Change management process
```

---

## Best Practices

- **Baseline**: Documenta configurazione
- **Test**: Verifica in staging
- **Layered defense**: Multiple controlli
- **Monitor**: Continuous monitoring
- **Review**: Audit periodici

## Riferimenti

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [NIST Hardening](https://www.nist.gov/cyberframework)
- [NSA Hardening Guides](https://www.nsa.gov/cybersecurity-guidance/)
- [Lynis](https://cisofy.com/lynis/)
