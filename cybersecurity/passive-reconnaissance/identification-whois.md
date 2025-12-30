# Domain Identification (WHOIS)

## Scopo

Recuperare informazioni sul dominio: registrant, email di contatto, name server, organizzazione e date di registrazione.

## Prerequisiti

- whois command
- Servizi online (who.is, whoxy)
- Conoscenza struttura WHOIS
- **Rispetto privacy GDPR**

---

## Overview Tecnica

WHOIS è un registro pubblico che, nonostante privacy e GDPR, continua a offrire dati strategici: provider, domini correlati, pattern di naming e informazioni utili per correlare infrastrutture.

## Strumenti Chiave

- whois standard
- whoxy / whoapi (servizi avanzati)
- amass (enumerazione correlata)

## Workflow Operativo

### Query base

```bash
whois target.com
```

### Estrazione dei NS

```bash
whois target.com | grep "Name Server"
```

### Pivoting su registrant (quando disponibile)

```bash
whois email@domain.com
```

## Use Case

La correlazione dei name server può evidenziare cluster di domini di test gestiti dalla stessa azienda.

## Quick Tips

I campi “Registrar Abuse Contact” spesso mostrano provider cloud → pivot verso infrastruttura reale.

---

## Best Practices

- **History**: Usa WHOIS storico
- **Correlation**: Correla NS e registrant
- **Privacy**: Rispetta GDPR
- **Multiple sources**: Confronta servizi
- **Documentation**: Salva risultati

## Riferimenti

[https://who.is](https://who.is)
