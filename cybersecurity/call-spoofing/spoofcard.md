# SpoofCard - Caller ID Spoofing Service

## Scopo

Questa guida descrive SpoofCard, uno dei servizi commerciali più noti per lo spoofing del Caller ID. Il servizio viene utilizzato in penetration testing per valutare la vulnerabilità delle organizzazioni agli attacchi di vishing (voice phishing).

## Prerequisiti

- Account SpoofCard con crediti
- Telefono per effettuare chiamate
- **Autorizzazione scritta** per i test
- Conoscenza delle normative locali
- Ambiente di test controllato

## Avvertenze Legali

> **ATTENZIONE**: L'uso di SpoofCard per scopi fraudolenti o illegali è perseguibile penalmente. Utilizza solo per:
>
> - Penetration testing autorizzato
> - Security awareness training
> - Test in ambienti controllati

---

## Panoramica SpoofCard

### Caratteristiche

- **Caller ID Spoofing**: Mostra qualsiasi numero al destinatario
- **Voice Changer**: Modifica la voce (maschile/femminile)
- **Call Recording**: Registra le conversazioni
- **Group Calling**: Chiamate di gruppo
- **SMS Spoofing**: Invia SMS con mittente personalizzato

### Funzionamento

```
1. Chiami numero di accesso SpoofCard
2. Inserisci PIN del tuo account
3. Inserisci numero da visualizzare (spoof)
4. Inserisci numero destinatario
5. La chiamata parte con caller ID falsificato
```

---

## Utilizzo

### Via Telefono

```
1. Chiama: +1-XXX-XXX-XXXX (numero accesso locale)
2. PIN: [Il tuo PIN]
3. Numero da mostrare: +39 02 1234567
4. Numero da chiamare: +39 333 1234567
5. Opzioni aggiuntive: 
   - Premi 1 per voice changer
   - Premi 2 per registrare
```

### Via App Mobile

```
1. Scarica app SpoofCard
2. Login con credenziali
3. Configura:
   - Display Number: numero da mostrare
   - Destination: numero da chiamare
   - Voice Changer: On/Off
   - Recording: On/Off
4. Premi "Call"
```

### Via Web

```
1. Accedi a spoofcard.com
2. Vai a "Make a Call"
3. Inserisci:
   - Your Number: tuo numero reale
   - Display Number: numero spoofed
   - Destination: numero target
4. Clicca "Place Call"
5. Rispondi alla callback
```

---

## Scenari di Penetration Testing

### Scenario 1: IT Support Impersonation

```
Display Number: Numero switchboard aziendale
Script: "Chiamo dall'IT, il suo computer ha un virus..."
Obiettivo: Valutare se l'utente segue istruzioni non verificate
```

### Scenario 2: Executive Fraud (CEO Fraud)

```
Display Number: Numero ufficio CEO
Script: "Sono [CEO], ho bisogno urgente di un bonifico..."
Obiettivo: Testare procedure di verifica per richieste finanziarie
```

### Scenario 3: Helpdesk Credentials

```
Display Number: Numero Helpdesk
Script: "Abbiamo un problema col suo account, mi serve la password..."
Obiettivo: Verificare se gli utenti rivelano credenziali
```

---

## Contromisure e Detection

### Tecniche di Rilevamento

- **Callback Verification**: Richiamata su numero ufficiale
- **STIR/SHAKEN**: Verifica autenticità caller ID
- **Caller ID Reputation**: Database numeri sospetti
- **Behavioral Analysis**: Pattern chiamate anomale

### Implementazione Aziendale

```
Policy di Sicurezza Telefonica:
1. Mai fornire password/PIN al telefono
2. Verificare sempre l'identità con callback
3. Richieste urgenti = Red flag
4. Segnalare chiamate sospette al SOC
```

### Formazione Utenti

- Simulazioni periodiche di vishing
- Training su red flags
- Procedure di escalation
- Reward per segnalazioni corrette

---

## Limitazioni

### Tecniche

- Alcuni carrier filtrano caller ID sospetti
- STIR/SHAKEN può marcare chiamate non verificate
- Numeri internazionali possono avere restrizioni
- Qualità audio può variare

### Legali

- Illegale per frode o molestie
- Registrazione richiede consenso in molte giurisdizioni
- Normative variano per paese
- Responsabilità penale per uso improprio

---

## Workflow per Security Assessment

```
1. AUTORIZZAZIONE
   └── Ottieni permesso scritto
   └── Definisci scope (numeri, scenari)
   └── Verifica compliance legale

2. PREPARAZIONE
   └── Crea script realistici
   └── Configura account SpoofCard
   └── Prepara modulo di tracking

3. ESECUZIONE
   └── Effettua chiamate secondo piano
   └── Documenta ogni interazione
   └── Non forzare se rifiutato

4. ANALISI
   └── Calcola tasso di successo
   └── Identifica pattern
   └── Analizza risposte

5. REPORTING
   └── Risultati quantitativi
   └── Esempi anonimizzati
   └── Raccomandazioni
   └── Piano formazione
```

---

## Best Practices

- **Consenso informato**: Il cliente deve autorizzare i test
- **Scope chiaro**: Solo numeri approvati
- **Non arrecare danno**: Scenari realistici ma non dannosi
- **Documentazione**: Log completo di ogni chiamata
- **Debriefing**: Informa i partecipanti dopo il test
- **Confidenzialità**: Proteggi i dati raccolti
- **Legal review**: Verifica conformità normativa

## Riferimenti

- [SpoofCard Official](https://www.spoofcard.com/)
- [FCC Caller ID Rules](https://www.fcc.gov/consumers/guides/spoofing-and-caller-id)
- [STIR/SHAKEN](https://www.fcc.gov/call-authentication)
- [Social Engineering Framework](https://www.social-engineer.org/)
