# SSL Certificates Recon

## Scopo

Analizzare certificati TLS per ottenere subdomini, versioni, cipher suite e configurazioni potenzialmente deboli.

## Prerequisiti

- openssl, sslscan
- Accesso a crt.sh
- Conoscenza TLS/SSL
- Browser con developer tools

---

## Overview Tecnica

I certificati espongono SAN (Subject Alternative Names), informazioni su CA, scadenze, protocolli abilitati e configurazioni obsolete. Perfetti per scovare ambienti di staging dimenticati.

## Strumenti Chiave

- sslscan: analisi delle cipher suite.  
- openssl: dump certificati.  
- crt.sh: ricerca dei certificati pubblici.  
- aha: conversione HTML terminal output.

## Workflow Operativo

### Certificati pubblici via crt.sh

```bash
curl "https://crt.sh/?q=%.target.com&output=json"
```

### Analisi certificato remoto

```bash
openssl s_client -connect target.com:443 -showcerts
```

### Cipher suite e protocolli

```bash
sslscan target.com
```

## Use Case

Il SAN di un certificato rivela spesso subdomini non indicizzati, utili per attacchi mirati.

## Quick Tips

Attenzione a TLS 1.0/1.1: spesso presenti su vecchi ambienti.

---

## Best Practices

- **SAN analysis**: Estrai tutti i SAN
- **Historical**: Cerca certificati scaduti
- **Wildcards**: Identifica pattern
- **Cipher check**: Verifica sicurezza
- **Expiration**: Nota scadenze

## Riferimenti

[https://crt.sh](https://crt.sh)
