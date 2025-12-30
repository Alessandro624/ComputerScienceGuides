# DNS Lookup & Enumeration

## Scopo

Mappare la struttura DNS del target per identificare host, sottodomini, mail server e potenziali entry point.

## Prerequisiti

- dig, nslookup, host
- dnsrecon, dnsenum
- Conoscenza record DNS
- **Autorizzazione per zone transfer**

---

## Overview Tecnica

Il DNS rivela molto più di quanto sembri: record MX, TXT, SPF, SRV e CNAME mostrano architetture interne, servizi esterni e configurazioni obsolete. L’enumerazione passiva rivela informazioni critiche senza toccare direttamente il server principale.

## Strumenti Chiave

- dig: interrogazioni DNS granulari.  
- dnsrecon: brute force e zone enumeration.  
- host/nslookup: risoluzione rapida IP ↔ dominio.  
- theHarvester: ricerca passiva di record e subdomini.

## Workflow Operativo

### Query standard

```bash
dig target.com ANY
```

### MX e SPF (e-mail)

```bash
dig target.com MX
dig target.com TXT
```

### Reverse lookup

```bash
host 1.2.3.4
```

### Enumerazione con dnsrecon

```bash
dnsrecon -d target.com -t std
```

## Use Case

Record TXT e SPF spesso contengono provider esterni e domini “nascosti” utilizzati per invio email.

## Quick Tips

Verifica sempre i CNAME: rivelano servizi cloud e applicazioni terze.

---

## Best Practices

- **Multiple servers**: Query diversi DNS
- **Record completi**: Non fermarti ad A/AAAA
- **Historical**: Usa SecurityTrails per storico
- **Passive first**: Prima passivo, poi attivo
- **Documentation**: Mappa completa DNS

## Riferimenti

[https://linux.die.net/man/1/dig](https://linux.die.net/man/1/dig)
