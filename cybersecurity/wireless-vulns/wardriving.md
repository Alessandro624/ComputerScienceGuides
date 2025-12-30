# Wardriving

## Scopo

Questa guida copre il wardriving, la pratica di mappare reti WiFi da un veicolo in movimento. Include strumenti, tecniche e considerazioni legali per security assessment.

## Prerequisiti

- Laptop con Kali Linux
- Scheda WiFi con monitor mode
- GPS USB (opzionale ma consigliato)
- Antenna esterna ad alto guadagno
- **Autorizzazione** per assessment specifici

## Installazione

```bash
sudo apt-get update
sudo apt-get install kismet airodump-ng gpsd
```

---

## Hardware Consigliato

### Schede WiFi

| Modello | Chipset | Note |
|---------|---------|------|
| Alfa AWUS036ACH | Realtek | Dual band, potente |
| Alfa AWUS036NHA | Atheros AR9271 | Affidabile |
| TP-Link TL-WN722N v1 | Atheros AR9271 | Economico |

### GPS

```bash
# GPS USB economici funzionano bene
# Configura gpsd
sudo gpsd /dev/ttyUSB0 -F /var/run/gpsd.sock
```

### Antenne

- **Omnidirezionale**: Copertura 360°
- **Direzionale**: Maggior range in una direzione
- **Guadagno**: 5-9 dBi consigliato

---

## Strumenti

### Kismet

```bash
# Avvio
sudo kismet

# Accedi web UI
# http://localhost:2501

# CLI mode
sudo kismet -c wlan0

# Con GPS
sudo kismet -c wlan0 --override wardrive
```

### Configurazione Kismet

```bash
# /etc/kismet/kismet.conf
source=wlan0:type=linuxwifi
gps=gpsd:host=localhost,port=2947
log_types=kismet,wiglecsv,pcapng
```

### Airodump-ng

```bash
# Monitor mode
sudo airmon-ng start wlan0

# Scan con GPS
sudo airodump-ng --gpsd wlan0mon -w wardriving_results

# Band specifico
sudo airodump-ng --band abg wlan0mon
```

### WiFi Pineapple

```
# Hardware dedicato
# Recon mode per wardriving
# Log automatico GPS + reti
```

---

## Workflow

### 1. Setup

```bash
# Abilita GPS
sudo gpsd /dev/ttyUSB0

# Verifica GPS
gpsmon

# Avvia Kismet
sudo kismet -c wlan0
```

### 2. Raccolta Dati

```bash
# Guida lentamente (20-40 km/h)
# Mantieni antenna stabile
# Evita interferenze (telefono, bluetooth)
```

### 3. Analisi

```bash
# Kismet genera diversi file:
# - .kismet: Database SQLite
# - .pcapng: Packet capture
# - .wiglecsv: Per upload su WiGLE
```

### 4. Visualizzazione

```bash
# Import in Google Earth
# Converti in KML
kismetdb_to_kml --in file.kismet --out results.kml

# Upload su WiGLE
# https://wigle.net
```

---

## Analisi Risultati

### Query Database Kismet

```bash
# SQLite
sqlite3 file.kismet

# Reti aperte
SELECT * FROM devices WHERE crypt='None';

# WEP
SELECT * FROM devices WHERE crypt='WEP';

# Statistiche
SELECT crypt, COUNT(*) FROM devices GROUP BY crypt;
```

### Export

```bash
# CSV
kismetdb_to_csv --in file.kismet --out results.csv

# WiGLE format
kismetdb_to_wiglecsv --in file.kismet --out wigle.csv
```

---

## Mappe

### WiGLE

```
1. Crea account su wigle.net
2. Upload wiglecsv
3. Visualizza heatmap globale
4. API per query programmatiche
```

### Creazione Mappe Custom

```python
import folium
import csv

m = folium.Map(location=[45.0, 9.0], zoom_start=12)

with open('results.csv') as f:
    reader = csv.DictReader(f)
    for row in reader:
        folium.Marker(
            [float(row['lat']), float(row['lon'])],
            popup=row['ssid']
        ).add_to(m)

m.save('wardriving_map.html')
```

---

## Considerazioni Legali

### Generalmente Legale

- Ricevere segnali radio in aree pubbliche
- Mappare reti visibili
- Non accedere a reti protette

### Potenzialmente Illegale

- Accesso a reti senza autorizzazione
- Cattura traffico di terzi
- Violazione privacy in alcune giurisdizioni

### Best Practices Legali

- Solo mapping passivo
- Non tentare accesso
- Rispetta normative locali
- Consulta legale se dubbi

---

## Applicazioni Security

### Per Organizzazioni

```
- Verifica copertura propria rete
- Identifica rogue AP
- Valuta esposizione perimetrale
- Audit configurazioni (WEP/open)
```

### Report

```markdown
# Wardriving Assessment Report

## Executive Summary
Identificate X reti nell'area target

## Findings
- Reti aperte: N
- Reti WEP: N
- Reti WPA/WPA2: N
- Reti WPA3: N

## Rogue AP Potenziali
[Lista SSID simili a quelli aziendali]

## Raccomandazioni
- Disabilitare SSID broadcast
- Migrare da WEP
- Implementare 802.1X
```

---

## Best Practices

- **Passivo**: Solo ascolto, mai trasmissione
- **Anonimato**: Non pubblicare dati sensibili
- **Scope**: Definisci area e obiettivi
- **Legal**: Verifica normative locali
- **Etica**: Non sfruttare vulnerabilità trovate
- **Report**: Segnala reti a rischio se appropriato

## Riferimenti

- [Kismet Documentation](https://www.kismetwireless.net/docs/)
- [WiGLE](https://wigle.net/)
- [Aircrack-ng Suite](https://www.aircrack-ng.org/)
