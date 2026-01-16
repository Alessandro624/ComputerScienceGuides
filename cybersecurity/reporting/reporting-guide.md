# Reporting Guide

## Scopo

Questa guida copre best practices per la creazione di report professionali di penetration test e security assessment, dalla struttura alla presentazione dei risultati.

## Prerequisiti

- Assessment completato
- Note e log delle attività
- Screenshot e evidence
- Template report

---

## Tools per Reporting

| Tool | Tipo | Uso |
|------|------|-----|
| Dradis | Open source | Collaboration platform |
| SysReptor | Open source | Report generation |
| Serpico | Open source | Report management |
| PlexTrac | Commercial | Full platform |

---

## Struttura Report

### Executive Summary

```
Destinatari: C-Level, management
Contenuto:
- Overview assessment
- Risultati chiave
- Risk rating complessivo
- Raccomandazioni prioritarie
- Timeline remediation suggerita

Lunghezza: 1-2 pagine
```

### Scope e Metodologia

```
- Obiettivi del test
- Sistemi/applicazioni in scope
- Sistemi esclusi
- Timeframe
- Tipo di test (black/gray/white box)
- Standard seguiti (OWASP, PTES, OSSTMM)
- Tools utilizzati
- Limitazioni riscontrate
```

### Technical Findings

```
Per ogni vulnerabilità:
1. Titolo descrittivo
2. Severity (Critical/High/Medium/Low/Info)
3. CVSS Score
4. Sistemi affetti
5. Descrizione tecnica
6. Proof of Concept (steps)
7. Evidence (screenshot, output)
8. Impatto business
9. Raccomandazioni remediation
10. Riferimenti (CVE, CWE)
```

### Risk Rating

| Severity | CVSS | Descrizione |
|----------|------|-------------|
| Critical | 9.0-10.0 | Compromissione completa, azione immediata |
| High | 7.0-8.9 | Impatto significativo, fix urgente |
| Medium | 4.0-6.9 | Impatto moderato, pianificare fix |
| Low | 0.1-3.9 | Impatto limitato, miglioramento |
| Info | 0.0 | Informativo, best practice |

---

## Finding Template

```markdown
## [SEV-01] SQL Injection in Login Form

**Severity**: High (CVSS 8.6)
**CWE**: CWE-89
**Location**: https://target.com/login.php

### Descrizione
L'applicazione non valida correttamente l'input utente nel campo 
username, permettendo l'injection di query SQL arbitrarie.

### Steps to Reproduce
1. Navigare a https://target.com/login
2. Nel campo username inserire: `admin' OR '1'='1`
3. Password qualsiasi
4. Click Login
5. Accesso come admin ottenuto

### Evidence
![SQL Injection Evidence](images/sqli-001.png)

### Impatto
- Bypass autenticazione
- Accesso dati sensibili
- Potenziale RCE via xp_cmdshell

### Remediation
1. Utilizzare prepared statements/parameterized queries
2. Implementare input validation
3. Applicare principio least privilege a DB user

### Riferimenti
- https://owasp.org/www-community/attacks/SQL_Injection
- https://cwe.mitre.org/data/definitions/89.html
```

---

## Evidence Collection

### Screenshot

```bash
# Annotare screenshot con:
- Data/ora
- Tool utilizzato
- Parametri
- Output rilevante

# Tools:
- Flameshot
- Greenshot
- ShareX
```

### Command Output

```bash
# Salvare output con timestamp
nmap -sV target | tee -a nmap_$(date +%Y%m%d_%H%M%S).txt

# Includere comando completo
echo "Command: nmap -sV -p- target" >> scan_log.txt
```

### Video

```
Per vulnerability complesse:
- PoC video walkthrough
- Dimostra impact chiaramente
- Tools: OBS, SimpleScreenRecorder
```

---

## Tools per Reporting

### Note-Taking

| Tool | Uso |
|------|-----|
| Obsidian | Markdown, linking |
| CherryTree | Gerarchico, CTF |
| Notion | Collaborativo |
| Joplin | Open source |

### Report Generation

| Tool | Formato |
|------|---------|
| Dradis | Collaborativo, multi-format |
| Faraday | IPE platform |
| PlexTrac | Enterprise |
| SysReptor | Open source |

### Templates

```bash
# Offensive Security
# SANS
# Custom aziendale
```

---

## Writing Tips

### Chiarezza

```
DO:
- Linguaggio chiaro e conciso
- Termini tecnici spiegati
- Acronimi definiti
- Sentences brevi

DON'T:
- Gergo eccessivo
- Paragrafi lunghi
- Assunzioni non verificate
- Linguaggio vago
```

### Evidence

```
DO:
- Screenshot con annotazioni
- Timestamp su tutto
- Comandi completi
- Output rilevante

DON'T:
- Screenshot non leggibili
- Evidence mancante
- Informazioni sensibili esposte
- PII non redacted
```

### Recommendations

```
DO:
- Actionable e specifiche
- Prioritizzate
- Reference a standard
- Quick wins identificati

DON'T:
- Generiche
- Impossibili da implementare
- Senza priorità
- Senza contesto
```

---

## Delivery

### Pre-Delivery

```
- Review spelling/grammar
- Verify evidence inclusa
- Redact sensitive data
- PDF security (password)
- Controllo link interni
```

### Presentation

```
- Executive briefing
- Technical walkthrough
- Q&A session
- Remediation discussion
- Timeline agreement
```

### Post-Delivery

```
- Supporto clarification
- Retest quando requested
- Verifica remediation
- Follow-up report
```

---

## Compliance Reporting

### PCI-DSS

```
Requisiti specifici:
- Quarterly scans (ASV)
- Annual pentest
- Format specifico
- Remediation tracking
```

### SOC 2

```
- Control testing
- Evidence documentation
- Exception handling
- Remediation tracking
```

---

## Report Checklist

```
[ ] Executive Summary completo
[ ] Scope definito
[ ] Metodologia descritta
[ ] Finding completi con evidence
[ ] CVSS scores corretti
[ ] Recommendations actionable
[ ] Appendici (raw output, etc.)
[ ] Spelling/grammar check
[ ] Sensitive data redacted
[ ] PDF generato e secured
[ ] Backup creato
```

---

## Best Practices

- **Accuracy**: Verify ogni finding
- **Clarity**: Audience-appropriate
- **Evidence**: Sempre documentare
- **Timeliness**: Deliver on schedule
- **Professionalism**: Formatting consistente

## Riferimenti

- [PTES Reporting](http://www.pentest-standard.org/index.php/Reporting)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Dradis](https://dradisframework.com/)
- [SysReptor](https://github.com/Syslifters/sysreptor)
