# OWASP Testing Guide

## Scopo

Questa guida riassume la metodologia OWASP Web Security Testing Guide (WSTG), fornendo una checklist strutturata per penetration test di applicazioni web.

## Prerequisiti

- Conoscenza web security
- Burp Suite o OWASP ZAP
- Familiarità con OWASP Top 10
- **Autorizzazione per testing**

---

## Fasi del Testing

```
1. Information Gathering
2. Configuration and Deployment Testing
3. Identity Management Testing
4. Authentication Testing
5. Authorization Testing
6. Session Management Testing
7. Input Validation Testing
8. Error Handling Testing
9. Cryptography Testing
10. Business Logic Testing
11. Client-Side Testing
12. API Testing
```

---

## 1. Information Gathering

### WSTG-INFO-01: Conduct Search Engine Discovery

```bash
# Google dorks
site:target.com filetype:pdf
site:target.com inurl:admin
site:target.com intitle:"index of"

# Bing, DuckDuckGo
```

### WSTG-INFO-02: Fingerprint Web Server

```bash
whatweb https://target.com
nmap -sV -p 80,443 target.com
curl -I https://target.com
```

### WSTG-INFO-03: Review Webserver Metafiles

```bash
curl https://target.com/robots.txt
curl https://target.com/sitemap.xml
curl https://target.com/.well-known/security.txt
```

### WSTG-INFO-04: Enumerate Applications

```bash
# Subdomain enumeration
subfinder -d target.com
amass enum -d target.com

# Virtual hosts
ffuf -u https://target.com -H "Host: FUZZ.target.com" -w subdomains.txt
```

### WSTG-INFO-05: Review Webpage Content

```
- Commenti HTML
- JavaScript files
- Source maps
- API endpoints in JS
```

### WSTG-INFO-08: Fingerprint Web Application Framework

```bash
# Wappalyzer
# BuiltWith
# WhatRuns

# Manuale
curl -s https://target.com | grep -i "generator"
```

---

## 2. Configuration Testing

### WSTG-CONF-01: Test Network Configuration

```bash
# SSL/TLS
sslscan target.com
testssl.sh target.com

# HTTP methods
nmap -p 443 --script http-methods target.com
```

### WSTG-CONF-02: Test Application Platform Configuration

```
- Directory listing
- Default pages
- Backup files (.bak, .old, ~)
- Debug mode
```

### WSTG-CONF-05: Enumerate Infrastructure

```bash
# Reverse DNS
host IP_ADDRESS

# Autonomous System
whois -h whois.cymru.com IP_ADDRESS
```

### WSTG-CONF-06: Test HTTP Methods

```bash
curl -X OPTIONS https://target.com -i
curl -X TRACE https://target.com -i
curl -X PUT https://target.com/test.txt -d "test"
```

---

## 3. Identity Management

### WSTG-IDNT-01: Test Role Definitions

```
- Identifica ruoli (admin, user, guest)
- Documenta permessi per ruolo
- Verifica separazione privilegi
```

### WSTG-IDNT-02: Test User Registration

```
- Self-registration
- Validation bypass
- Duplicate accounts
- Email verification bypass
```

### WSTG-IDNT-04: Test Account Enumeration

```bash
# Response differenti per user valido/invalido
# Timing differences
# Error messages

# Forgot password enumeration
curl -X POST target.com/forgot -d "email=valid@target.com"
curl -X POST target.com/forgot -d "email=invalid@random.com"
```

---

## 4. Authentication Testing

### WSTG-ATHN-01: Test Credentials Transport

```
- HTTPS required?
- Credentials in URL?
- Form action HTTPS?
```

### WSTG-ATHN-02: Test Default Credentials

```bash
# Default creds
admin:admin
admin:password
root:root
test:test

# Device-specific defaults
# Application-specific defaults
```

### WSTG-ATHN-03: Test Weak Lock Out

```bash
# Brute force test
hydra -l admin -P passwords.txt target http-post-form \
    "/login:user=^USER^&pass=^PASS^:Invalid"

# Verifica lockout dopo N tentativi
```

### WSTG-ATHN-04: Test Bypass Authentication

```
- SQL injection in login
- Authentication parameter manipulation
- Direct page access
- Session prediction
```

### WSTG-ATHN-07: Test Weak Password Policy

```
- Lunghezza minima
- Complessità
- Password comuni
- Password history
```

---

## 5. Authorization Testing

### WSTG-ATHZ-01: Test Directory Traversal

```
../../../etc/passwd
..%2f..%2f..%2fetc/passwd
....//....//....//etc/passwd
```

### WSTG-ATHZ-02: Test Bypass Authorization

```
# IDOR
GET /api/users/1001  # Tuo ID
GET /api/users/1002  # Altro ID

# Forced browsing
/admin/
/internal/
```

### WSTG-ATHZ-03: Test Privilege Escalation

```
# Horizontal (stesso livello)
Accesso dati altri utenti

# Vertical (livello superiore)
User → Admin
```

---

## 6. Session Management

### WSTG-SESS-01: Test Session Management Schema

```
- Token randomness (Burp Sequencer)
- Token length
- Token in URL vs cookie
- Token regeneration after login
```

### WSTG-SESS-02: Test Cookie Attributes

```
Set-Cookie: session=abc;
  HttpOnly;     [x]
  Secure;       [x]
  SameSite;     [x]
  Path=/;       [x]
```

### WSTG-SESS-03: Test Session Fixation

```
1. Ottieni session ID non autenticato
2. Forza vittima a usarlo
3. Vittima si autentica
4. Usa session ID (ora autenticato)
```

### WSTG-SESS-05: Test CSRF

```html
<form action="https://target.com/transfer" method="POST">
    <input name="to" value="attacker">
    <input name="amount" value="1000">
</form>
<script>document.forms[0].submit()</script>
```

---

## 7. Input Validation

### WSTG-INPV-01: Test Reflected XSS

```html
<script>alert('XSS')</script>
<img src=x onerror=alert(1)>
"><script>alert(1)</script>
```

### WSTG-INPV-02: Test Stored XSS

```
- Commenti
- Profili
- Message boards
- File upload (SVG, HTML)
```

### WSTG-INPV-05: Test SQL Injection

```sql
' OR '1'='1
' UNION SELECT NULL--
'; DROP TABLE--
```

### WSTG-INPV-12: Test Command Injection

```bash
; id
| ls
$(whoami)
`cat /etc/passwd`
```

### WSTG-INPV-11: Test Code Injection

```php
${7*7}
{{7*7}}
<%= 7*7 %>
```

---

## 8. Error Handling

### WSTG-ERRH-01: Test Improper Error Handling

```
- Stack traces visibili
- Database errors con query
- Path disclosure
- Version disclosure
```

### WSTG-ERRH-02: Test Stack Traces

```bash
# Forza errori
curl "https://target.com/page?id='"
curl "https://target.com/page?id=-1"
curl "https://target.com/nonexistent"
```

---

## 9. Cryptography

### WSTG-CRYP-01: Test Weak TLS

```bash
sslscan target.com
testssl.sh target.com
nmap --script ssl-enum-ciphers -p 443 target.com
```

### WSTG-CRYP-02: Test Padding Oracle

```
- Timing differences
- Error messages
- Tools: PadBuster, Padding Oracle Attacker
```

### WSTG-CRYP-03: Test Sensitive Data in Storage

```
- Password hashing (bcrypt, scrypt, Argon2)
- Data encryption at rest
- Key management
```

---

## 10. Business Logic

### WSTG-BUSL-01: Test Business Logic Flaws

```
- Price manipulation
- Quantity tampering
- Workflow bypass
- Feature abuse
```

### WSTG-BUSL-09: Test File Upload

```
- Extension bypass (file.php.jpg)
- Content-Type manipulation
- Size limits
- Directory traversal in filename
```

---

## 11. Client-Side Testing

### WSTG-CLNT-01: Test DOM-Based XSS

```javascript
// Sources
location.hash
location.search
document.referrer

// Sinks
innerHTML
document.write()
eval()
```

### WSTG-CLNT-09: Test Clickjacking

```html
<iframe src="https://target.com/sensitive-action"></iframe>
```

---

## Checklist Rapida

```
[ ] Information gathering completo
[ ] SSL/TLS configuration check
[ ] Authentication bypass attempts
[ ] Authorization/IDOR testing
[ ] Session management review
[ ] XSS testing (reflected, stored, DOM)
[ ] SQL injection testing
[ ] Command injection testing
[ ] File upload testing
[ ] Business logic testing
[ ] Error handling review
[ ] Security headers check
```

---

## Best Practices

- **Metodico**: Segui la checklist sistematicamente
- **Documentazione**: Log ogni test eseguito
- **Riproducibilità**: Steps chiari per ogni finding
- **Priorità**: Focus su vulnerabilità critiche
- **Scope**: Rispetta limiti concordati

## Riferimenti

- [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Testing Checklist](https://github.com/OWASP/wstg/tree/master/checklist)
- [OWASP Top 10](https://owasp.org/Top10/)
- [PortSwigger Testing](https://portswigger.net/web-security)
