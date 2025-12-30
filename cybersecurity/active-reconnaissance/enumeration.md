# Enumeration

## Scopo

Questa guida copre le tecniche di enumerazione per estrarre informazioni dettagliate da servizi, utenti, share e risorse di rete. L'enumerazione è il processo di raccolta attiva di informazioni su un target dopo aver identificato i servizi disponibili.

## Prerequisiti

- Accesso ai servizi target (porte aperte)
- Strumenti di enumerazione (enum4linux, ldapsearch, smbclient)
- Kali Linux o distribuzione con tool di pentesting
- **Autorizzazione scritta** per il testing

## Installazione

```bash
# Installazione strumenti
sudo apt-get update
sudo apt-get install enum4linux smbclient ldap-utils snmp onesixtyone
```

---

## Enumerazione SMB/CIFS

### Enum4linux

```bash
# Enumerazione completa
enum4linux -a target_ip

# Solo utenti
enum4linux -U target_ip

# Solo share
enum4linux -S target_ip

# Solo gruppi
enum4linux -G target_ip

# Password policy
enum4linux -P target_ip
```

### SMBClient

```bash
# Lista share (null session)
smbclient -L //target_ip -N

# Connessione a share
smbclient //target_ip/share_name -U username

# Connessione anonima
smbclient //target_ip/share_name -N

# Download ricorsivo
smbclient //target_ip/share -N -c 'recurse; prompt; mget *'
```

### SMBMap

```bash
# Enumerazione share con permessi
smbmap -H target_ip

# Con credenziali
smbmap -H target_ip -u user -p password

# Lista file ricorsiva
smbmap -H target_ip -R share_name
```

### CrackMapExec

```bash
# Enumerazione SMB
crackmapexec smb target_ip

# Con credenziali
crackmapexec smb target_ip -u user -p password

# Enumerazione utenti
crackmapexec smb target_ip -u user -p password --users

# Enumerazione share
crackmapexec smb target_ip -u user -p password --shares
```

---

## Enumerazione LDAP

### Ldapsearch

```bash
# Query anonima base DN
ldapsearch -x -H ldap://target_ip -b "dc=domain,dc=com"

# Tutti gli oggetti
ldapsearch -x -H ldap://target_ip -b "dc=domain,dc=com" "(objectClass=*)"

# Solo utenti
ldapsearch -x -H ldap://target_ip -b "dc=domain,dc=com" "(objectClass=user)"

# Con autenticazione
ldapsearch -x -H ldap://target_ip -D "cn=admin,dc=domain,dc=com" -w password -b "dc=domain,dc=com"

# Attributi specifici
ldapsearch -x -H ldap://target_ip -b "dc=domain,dc=com" "(objectClass=user)" sAMAccountName mail
```

### Ldapdomaindump

```bash
# Dump completo dominio
ldapdomaindump -u 'DOMAIN\user' -p 'password' target_ip

# Output in formato specifico
ldapdomaindump -u 'DOMAIN\user' -p 'password' -o output_dir target_ip
```

---

## Enumerazione DNS

### Dig

```bash
# Record A
dig @dns_server domain.com A

# Record MX
dig @dns_server domain.com MX

# Record NS
dig @dns_server domain.com NS

# Tutti i record
dig @dns_server domain.com ANY

# Zone transfer
dig @dns_server domain.com AXFR

# Reverse lookup
dig @dns_server -x ip_address
```

### DNSrecon

```bash
# Enumerazione standard
dnsrecon -d domain.com

# Zone transfer
dnsrecon -d domain.com -t axfr

# Brute force subdomain
dnsrecon -d domain.com -D wordlist.txt -t brt
```

### Fierce

```bash
# Enumerazione DNS
fierce --domain domain.com

# Con DNS server specifico
fierce --domain domain.com --dns-servers ns1.domain.com
```

---

## Enumerazione SNMP

### Onesixtyone

```bash
# Brute force community strings
onesixtyone -c community_strings.txt target_ip

# Scansione range
onesixtyone -c community_strings.txt -i hosts.txt
```

### SNMPwalk

```bash
# Enumerazione base (v1/v2c)
snmpwalk -v2c -c public target_ip

# OID specifico (utenti Windows)
snmpwalk -v2c -c public target_ip 1.3.6.1.4.1.77.1.2.25

# Processi in esecuzione
snmpwalk -v2c -c public target_ip 1.3.6.1.2.1.25.4.2.1.2

# Software installato
snmpwalk -v2c -c public target_ip 1.3.6.1.2.1.25.6.3.1.2

# Porte TCP aperte
snmpwalk -v2c -c public target_ip 1.3.6.1.2.1.6.13.1.3
```

### SNMP-check

```bash
# Enumerazione completa
snmp-check target_ip -c public
```

---

## Enumerazione NFS

```bash
# Mostra export
showmount -e target_ip

# Monta share
mkdir /tmp/nfs
sudo mount -t nfs target_ip:/share /tmp/nfs

# Lista file
ls -la /tmp/nfs
```

---

## Enumerazione RPC

```bash
# RPC info
rpcinfo -p target_ip

# Rpcclient (SMB)
rpcclient -U "" -N target_ip

# Comandi rpcclient
rpcclient> enumdomusers
rpcclient> enumdomgroups
rpcclient> queryuser 0x1f4
rpcclient> getdompwinfo
```

---

## Enumerazione Web

### Gobuster

```bash
# Directory bruteforce
gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt

# Con estensioni
gobuster dir -u http://target -w wordlist.txt -x php,html,txt

# Subdomain enumeration
gobuster dns -d domain.com -w subdomains.txt
```

### Nikto

```bash
# Scansione vulnerabilità web
nikto -h http://target

# Con output file
nikto -h http://target -o report.html -Format htm
```

### WhatWeb

```bash
# Fingerprinting web
whatweb http://target

# Aggressivo
whatweb -a 3 http://target
```

---

## Workflow Operativo

1. **Identificazione servizi**: Usa nmap per identificare servizi attivi
2. **SMB/CIFS**: Enumera share, utenti e gruppi
3. **LDAP**: Estrai informazioni dal directory service
4. **DNS**: Cerca subdomain e record
5. **SNMP**: Estrai informazioni di sistema
6. **Web**: Enumera directory e vulnerabilità
7. **Documentazione**: Registra tutte le informazioni trovate

---

## Best Practices

- **Metodologia**: Segui un approccio sistematico per ogni servizio
- **Null Sessions**: Testa sempre sessioni anonime prima dell'autenticazione
- **Credenziali**: Prova credenziali di default comuni
- **Wordlist**: Usa wordlist appropriate per il contesto
- **Logging**: Mantieni traccia di tutti i tentativi
- **Correlazione**: Correla informazioni tra diversi servizi
- **Impatto**: Monitora l'impatto delle query sui servizi target

## Riferimenti

- [Enum4linux GitHub](https://github.com/CiscoCXSecurity/enum4linux)
- [HackTricks Enumeration](https://book.hacktricks.xyz/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
