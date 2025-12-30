# Search Engine Intelligence & Dorking

## Scopo

Sfruttare motori di ricerca e archivi pubblici per scoprire asset esposti, pagine sensibili, directory non indicizzate e infrastrutture storiche.

## Prerequisiti

- Browser
- Account Shodan/Censys
- Conoscenza Google Dorks
- Tool CLI (shodan-cli)

---

## Overview Tecnica

Google Dorking permette query mirate su file, directory, parametri vulnerabili e vecchie versioni di applicazioni web. Archivi come Web Archive e tool come Shodan permettono di analizzare versioni passate e dispositivi esposti.

## Strumenti Chiave

- Google Dorks  
- Wayback Machine  
- Shodan / Censys  
- Maltego  

## Workflow Operativo

### Ricerca file sensibili

```
site:target.com ext:sql | ext:bak | ext:env
```

### Directory esposte

```
intitle:"index of" "target.com"
```

### Versioni storiche

Wayback Machine → [https://web.archive.org/web/*/target.com](https://web.archive.org/web/*/target.com)

### Fingerprinting con Shodan

```bash
shodan search 'hostname:"target.com"'
```

## Use Case

Versioni archiviate di una webapp possono mostrare endpoint rimossi ma ancora presenti nel backend.

## Quick Tips

Non sovrastimare i dorks: meglio combinarli con enumerazione DNS e certificati.

---

## Best Practices

- **Combine sources**: Usa più motori
- **Historical**: Controlla Wayback Machine
- **Automation**: Script per dork ripetitivi
- **Documentation**: Salva URL trovati
- **Legal**: Rispetta robots.txt dove appropriato

## Riferimenti

[https://www.shodan.io](https://www.shodan.io)
