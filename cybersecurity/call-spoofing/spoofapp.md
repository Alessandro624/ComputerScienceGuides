# SpoofApp - Call Spoofing Applications

## Scopo

Questa guida descrive le applicazioni e i servizi per lo spoofing di Caller ID, utilizzati in contesti di penetration testing per testare la consapevolezza degli utenti e la sicurezza delle comunicazioni telefoniche. **L'uso non autorizzato dello spoofing telefonico è illegale nella maggior parte delle giurisdizioni.**

## Prerequisiti

- Smartphone (Android/iOS) o accesso web
- Account su piattaforma di spoofing
- Crediti/abbonamento per effettuare chiamate
- **Autorizzazione scritta** per i test
- Conoscenza delle leggi locali sul caller ID spoofing

## Avvertenze Legali

> **IMPORTANTE**: Lo spoofing del Caller ID è regolamentato o illegale in molti paesi:
>
> - **USA**: Legale solo per scopi legittimi (Truth in Caller ID Act)
> - **UK**: Illegale se usato per frode o molestie
> - **Italia**: Potenzialmente perseguibile se usato per ingannare
> - **UE**: Regolamentato dal GDPR e normative telecomunicazioni

---

## Servizi Commerciali

### SpoofApp (Discontinued)

SpoofApp era un'applicazione mobile che permetteva di modificare il caller ID. **Il servizio è stato chiuso**, ma esistono alternative simili.

### Alternative Attuali

#### SpoofCard

- Website: spoofcard.com
- Piattaforme: Web, Android, iOS
- Funzionalità: Caller ID spoofing, voice changer, call recording

#### SpoofTel

- Website: spooftel.com
- Piattaforme: Web
- Funzionalità: Caller ID spoofing, SMS spoofing

#### Bluff My Call

- Website: bluffmycall.com
- Piattaforme: Android, iOS
- Funzionalità: Caller ID spoofing, voice disguise

---

## Come Funziona

### Architettura Base

```
[Chiamante] → [Servizio Spoofing] → [Carrier Telefonico] → [Destinatario]
                     ↓
              Modifica Caller ID
              nel setup della chiamata
```

### Protocollo SIP

Lo spoofing sfrutta il campo "From" nell'intestazione SIP:

```
INVITE sip:destinatario@carrier.com SIP/2.0
Via: SIP/2.0/UDP 10.0.0.1:5060
From: <sip:+39123456789@spoofed.com>;tag=abc123
To: <sip:+39987654321@carrier.com>
```

---

## Utilizzo per Penetration Testing

### Scenario: Vishing Assessment

1. **Pianificazione**: Definisci obiettivi e target autorizzati
2. **Preparazione**: Crea script convincente (es. IT Support)
3. **Spoofing**: Configura caller ID del reparto IT aziendale
4. **Esecuzione**: Effettua chiamata al target
5. **Valutazione**: Documenta la risposta dell'utente
6. **Report**: Analizza risultati e fornisci raccomandazioni

### Script di Esempio

```
"Buongiorno, sono [Nome] dal supporto IT.
Abbiamo rilevato un problema di sicurezza sul suo account.
Per verificare la sua identità, potrebbe fornirmi..."
```

---

## Contromisure

### Per Organizzazioni

- **STIR/SHAKEN**: Implementa autenticazione caller ID
- **Call Authentication**: Verifica callback su numeri noti
- **Training**: Forma il personale su vishing attacks
- **Policy**: Definisci procedure per verifiche telefoniche

### Per Utenti

- **Verifica callback**: Richiama sempre su numeri ufficiali
- **Non fidarti del caller ID**: Può essere falsificato
- **Non fornire dati sensibili**: Nessuna azienda li chiede al telefono
- **Segnala sospetti**: Informa il team security

---

## Workflow Operativo

1. **Autorizzazione**: Ottieni permesso scritto dal cliente
2. **Scope**: Definisci numeri target e scenari
3. **Setup**: Configura servizio di spoofing
4. **Test**: Effettua chiamate di prova interne
5. **Esecuzione**: Lancia la campagna di vishing
6. **Raccolta dati**: Documenta ogni interazione
7. **Analisi**: Valuta tasso di successo
8. **Report**: Fornisci risultati e raccomandazioni

---

## Best Practices

- **Autorizzazione scritta**: Mai operare senza permesso esplicito
- **Scope limitato**: Solo numeri nel perimetro autorizzato
- **Recording consent**: Verifica legalità registrazione chiamate
- **No danni reali**: Non richiedere azioni dannose
- **Debriefing**: Informa i partecipanti dopo il test
- **Confidenzialità**: Proteggi i dati raccolti
- **Compliance**: Rispetta GDPR e normative locali

## Riferimenti

- [FCC Truth in Caller ID Act](https://www.fcc.gov/consumers/guides/spoofing-and-caller-id)
- [STIR/SHAKEN Framework](https://www.fcc.gov/call-authentication)
- [Social Engineering Framework](https://www.social-engineer.org/)
- [Vishing Awareness Training](https://www.knowbe4.com/)
