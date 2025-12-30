# OSINT

## Scopo

Raccogliere informazioni pubblicamente disponibili su domini, infrastrutture, persone e servizi, senza interagire direttamente con il target.

## Prerequisiti

- Connessione internet
- Tool OSINT (theHarvester, Recon-ng, SpiderFoot)
- Account per servizi (Shodan, Censys)
- **Comprensione limiti legali**

---

## Overview Tecnica

L’OSINT (Open Source Intelligence) consente di ricostruire l’ecosistema del target incrociando fonti aperte come certificati, subdomini, leak, metadati e asset esposti. È la prima fase di ogni engagement perché riduce i rischi di detection e guida le attività attive.

## Strumenti Chiave

- SpiderFoot: scanner OSINT completamente automatizzato.  
- Recon-ng: framework modulare tipo Metasploit.  
- Searchsploit: correlazione software rilevati ↔ exploit noti.  
- theHarvester: email, host, subdomain enumeration.  
- Shodan/Censys: mappatura servizi pubblici.  
- crt.sh: certificati → subdomini.

## Workflow Operativo

### Scansione OSINT completa con Spiderfoot

```bash
sfsf.py -s target.com -m all -o report
```

### Email & subdomain discovery

```bash
theHarvester -d target.com -b all
```

### Correlazione versioni software → exploit

```bash
searchsploit apache 2.4
```

## Use Case

La scoperta di subdomini “dev” tramite crt.sh spesso porta a superfici vulnerabili non monitorate dal reparto IT.

## Quick Tips

Incrocia sempre le fonti e conserva una mappa dei collegamenti: cert → dominio → leak → asset.

---

## Best Practices

- **Documentation**: Documenta tutte le fonti
- **Verification**: Verifica informazioni da più fonti
- **Legal**: Rispetta privacy e GDPR
- **Organization**: Usa tool per organizzare dati
- **Updates**: Riesegui periodicamente

## Riferimenti

[https://osintframework.com](https://osintframework.com)
[https://shodan.io](https://shodan.io)
