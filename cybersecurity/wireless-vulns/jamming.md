# WiFi Jamming

## Scopo

Questa guida fornisce informazioni educative sul jamming WiFi, una tecnica che interferisce con le comunicazioni wireless. **Il jamming è illegale nella maggior parte delle giurisdizioni.**

## Prerequisiti

- Conoscenza di radiofrequenze
- Ambiente di laboratorio schermato (Faraday cage)
- **Autorizzazione speciale** (es. laboratori di ricerca)

## Avvertenze Legali

> **ATTENZIONE LEGALE**:
>
> - Il jamming è **ILLEGALE** in quasi tutti i paesi
> - Viola le normative FCC (USA), ETSI (EU), AGCOM (Italia)
> - Può interferire con servizi di emergenza
> - Sanzioni penali e multe significative
> - Questa guida è **SOLO a scopo educativo**

---

## Tipi di Jamming

### Continuous Jamming

```
- Trasmissione continua sulla frequenza target
- Blocca completamente il canale
- Facile da rilevare
- Richiede molta energia
```

### Deceptive Jamming

```
- Trasmette frame validi ma inutili
- Consuma bandwidth
- Più difficile da rilevare
- Esempio: beacon flooding
```

### Reactive Jamming

```
- Attivo solo quando rileva trasmissioni
- Più efficiente energeticamente
- Difficile da implementare
- Richiede hardware specializzato
```

### Random Jamming

```
- Alterna jamming e sleep
- Risparmia energia
- Causa packet loss intermittente
```

---

## Frequenze WiFi

| Standard | Banda | Canali |
|----------|-------|--------|
| 802.11b/g/n | 2.4 GHz | 1-14 |
| 802.11a/n/ac | 5 GHz | 36-165 |
| 802.11ax (WiFi 6E) | 6 GHz | 1-233 |

---

## Tecniche di Mitigazione

### Spread Spectrum

```
- FHSS: Frequency Hopping Spread Spectrum
- DSSS: Direct Sequence Spread Spectrum
- Rende jamming meno efficace
```

### Antenna Directionality

```
- Antenne direzionali
- Limita esposizione a jammer
- Null steering verso fonte interferenza
```

### Adaptive Frequency Selection

```
- Cambia canale automaticamente
- DFS (Dynamic Frequency Selection)
- Evita canali interferiti
```

### Detection

```bash
# Monitoring RSSI anomalo
# Packet loss elevato
# Latenza aumentata
# WIDS alerts
```

---

## Detection Jamming

### Indicatori

- Packet loss improvviso e elevato (>50%)
- RSSI molto alto senza client visibili
- Impossibilità di associarsi
- Beacon interval irregolare

### Wireshark

```
# Frame retransmission elevate
wlan.fc.retry == 1

# Statistiche
# Statistics > Wireless > WLAN Traffic
```

### Spectrum Analyzer

```
# WiFi Analyzer (Android)
# Ubiquiti airView
# Wi-Spy
# Verifica occupazione spettro
```

---

## Contromisure

### Hardware

- **Faraday shielding**: Aree sensibili
- **Antenne direzionali**: Limita superficie attacco
- **Spectrum monitoring**: Rileva anomalie

### Software

- **Channel hopping**: Cambia canale dinamicamente
- **Redundancy**: Connessioni multiple
- **Wired backup**: Ethernet per sistemi critici

### Organizzative

- **Incident response**: Procedure per jamming
- **Physical security**: Limita accesso ad aree
- **Triangolazione**: Localizza fonte jammer

---

## Ricerca e Test Legali

### Ambiente Controllato

```
- Camera schermata (Faraday cage)
- Nessuna interferenza esterna
- Autorizzazioni specifiche
- Solo per ricerca accademica/industriale
```

### Alternative Legali

```
- Simulazioni software
- Attenuatori per limitare range
- Laboratori certificati
```

---

## Best Practices

- **Non farlo**: Il jamming è illegale e pericoloso
- **Studia teoria**: Comprendi RF senza implementare
- **Lab schermato**: Se autorizzato per ricerca
- **Contromisure**: Focus su detection e mitigation
- **Segnala**: Denuncia jamming alle autorità

## Riferimenti

- [FCC Jammer Enforcement](https://www.fcc.gov/general/jammer-enforcement)
- [IEEE 802.11 Standard](https://www.ieee802.org/11/)
- [RF Interference Guide](https://www.cisco.com/c/en/us/support/docs/wireless/5500-series-wireless-controllers/82463-interf-src.html)
