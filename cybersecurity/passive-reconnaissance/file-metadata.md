# File Metadata Analysis

## Scopo

Estrarre metadati da documenti, PDF, immagini e file multimediali per ottenere nomi host, utenti interni, percorsi macchina e software utilizzato.

## Prerequisiti

- exiftool
- FOCA (Windows)
- mat2 per sanitizzazione
- File da analizzare

---

## Overview Tecnica

I metadati vengono spesso trascurati ma rivelano hostname, versioni software, timestamp, geolocalizzazione e informazioni interne. Perfetti per OSINT e recon su infrastrutture aziendali.

## Strumenti Chiave

- Exiftool: estrazione metadati universale.  
- FOCA: analisi massiva documenti aziendali.  
- mat2: sanificazione metadati.

## Workflow Operativo

### Metadati completi con Exiftool

```bash
exiftool documento.pdf
```

### Estrazione massiva con FOCA (GUI)

Carica PDF/Word del dominio → estrae utenti, server, percorsi.

## Use Case

I PDF pubblicati dai dipendenti contengono spesso hostname interni utili per pivot successivi.

## Quick Tips

Occhio ai tag GPS nelle immagini: rivelano sedi e spostamenti.

---

## Best Practices

- **Bulk analysis**: Analizza molti file
- **Correlation**: Correla username/hostname
- **Software versions**: Nota versioni software
- **GPS data**: Estrai geolocalizzazione
- **Documentation**: Crea mappa utenti interni

## Riferimenti

[https://exiftool.org](https://exiftool.org)
