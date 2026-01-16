# Password Dumps & Credential Intelligence

## Scopo

Identificare credenziali compromesse per valutare il rischio di credential stuffing e password reuse.

## Prerequisiti

- h8mail, whatbreach
- Database leak locali
- API key per servizi
- **Autorizzazione e rispetto legale**

---

## Overview Tecnica

Raccogliere leak pubblici permette di stimare il rischio reale: dipendenti che riutilizzano password, account compromessi, domini interni esposti. È una delle tecniche più utilizzate nei pentest moderni.

## Strumenti Chiave

- h8mail: ricerca multi-source in leak pubblici.  
- pwndb: query onion service per credenziali compromesse.  
- whatbreach: correlazione breach → email.  
- scavenger / buster: dump automation.  
- leaklooker: ricerca di database esposti.  
- DeHashed: servizio commerciale per breach search.

## Workflow Operativo

### Ricerca di credenziali legate al dominio

```bash
h8mail -t email@target.com --local-db db/ --breach
```

### Verifica bulk utenti aziendali

```bash
h8mail -l employees.txt --breach
```

## Use Case

Scoprire password aziendali riutilizzate in vecchi leak è spesso il punto d’ingresso più realistico in un engagement.

## Quick Tips

Filtra i risultati: molti dump contengono dati non validi o incompleti.

---

## Best Practices

- **Verification**: Verifica validità credenziali
- **Scope**: Solo email in-scope
- **Legal**: Rispetta normative
- **Reporting**: Documenta responsabilmente
- **Cleanup**: Non conservare dati sensibili

## Riferimenti

[https://github.com/khast3x/h8mail](https://github.com/khast3x/h8mail)
