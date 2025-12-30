# Social-Engineer Toolkit (SET)

## Scopo

Questa guida fornisce una panoramica di SET (Social-Engineer Toolkit), uno dei framework più completi per simulare attacchi di social engineering. SET è utilizzato per testare la consapevolezza degli utenti e valutare la resistenza di un'organizzazione agli attacchi di ingegneria sociale.

## Prerequisiti

- Kali Linux o distribuzione con Python
- Permessi root/sudo
- Conoscenza di base di networking e web
- **Autorizzazione scritta** per i test
- Ambiente di lab controllato per i test

## Installazione

```bash
# Su Kali Linux (preinstallato)
setoolkit

# Installazione manuale
git clone https://github.com/trustedsec/social-engineer-toolkit.git
cd social-engineer-toolkit
pip3 install -r requirements.txt
python3 setup.py install
```

---

## Avvio e Menu Principale

```bash
sudo setoolkit
```

### Menu Principale

1. **Social-Engineering Attacks**: Attacchi di ingegneria sociale
2. **Penetration Testing (Fast-Track)**: Test di penetrazione rapidi
3. **Third Party Modules**: Moduli di terze parti
4. **Update the Social-Engineer Toolkit**: Aggiornamento
5. **Update SET configuration**: Configurazione
6. **Help, Credits, and About**: Aiuto

---

## Attacchi di Social Engineering

### 1. Spear-Phishing Attack Vector

Crea email di phishing mirate con allegati malevoli.

```
1) Social-Engineering Attacks
   1) Spear-Phishing Attack Vectors
      1) Perform a Mass Email Attack
      2) Create a FileFormat Payload
      3) Create a Social-Engineering Template
```

**Opzioni payload**:

- PDF con exploit
- Microsoft Word/Excel con macro
- Custom EXE/DLL

### 2. Website Attack Vector

Clona siti web per raccogliere credenziali.

```
1) Social-Engineering Attacks
   2) Website Attack Vectors
      1) Java Applet Attack Method
      2) Metasploit Browser Exploit Method
      3) Credential Harvester Attack Method
      4) Tabnabbing Attack Method
      5) Web Jacking Attack Method
      6) Multi-Attack Web Method
      7) HTA Attack Method
```

#### Credential Harvester

```
2) Website Attack Vectors
   3) Credential Harvester Attack Method
      1) Web Templates (Gmail, Facebook, Twitter)
      2) Site Cloner (clona qualsiasi sito)
      3) Custom Import
```

**Esempio Site Cloner**:

```
set:webattack> 2
[-] SET supports both HTTP and HTTPS
[-] Enter the url to clone: https://login.example.com

[*] Cloning the website: https://login.example.com
[*] This could take a little bit...

[*] Credential harvester is now listening below:
[*] http://your_ip

[*] Waiting for credentials...
```

### 3. Infectious Media Generator

Crea media USB/CD autorun malevoli.

```
1) Social-Engineering Attacks
   3) Infectious Media Generator
      1) Standard Metasploit Executable
      2) Standard Metasploit Executable w/ Encoding
```

### 4. Payload and Listener

Crea payload personalizzati con listener Metasploit.

```
1) Social-Engineering Attacks
   4) Create a Payload and Listener
      1) Windows Shell Reverse_TCP
      2) Windows Reverse_TCP Meterpreter
      3) Windows Reverse_TCP VNC DLL
      ...
```

### 5. Mass Mailer Attack

Invia email di massa per campagne di phishing.

```
1) Social-Engineering Attacks
   5) Mass Mailer Attack
      1) E-Mail Attack Single Email Address
      2) E-Mail Attack Mass Mailer
```

**Configurazione**:

```
set:mailer> 1
set:phishing> Send email to: victim@example.com
set:phishing> From address: support@trusted.com
set:phishing> Subject: Account Verification Required
set:phishing> Send HTML or plain: html
set:phishing> Enter the body of the message (press CTRL+C when done):
```

### 6. Arduino-Based Attack Vector

Utilizza Arduino per emulare HID keyboard.

### 7. Wireless Access Point Attack Vector

Crea access point malevolo per intercettare traffico.

### 8. QRCode Generator Attack Vector

Genera QR code che puntano a URL malevoli.

```
1) Social-Engineering Attacks
   8) QRCode Generator Attack Vector

Enter the URL: http://malicious-site.com
```

### 9. PowerShell Attack Vectors

Genera payload PowerShell per bypass antivirus.

```
1) Social-Engineering Attacks
   9) PowerShell Attack Vectors
      1) PowerShell Alphanumeric Shellcode Injector
      2) PowerShell Reverse Shell
      3) PowerShell Bind Shell
      4) PowerShell Dump SAM Database
```

---

## Configurazione SET

File: `/etc/setoolkit/set.config`

```ini
# Email settings
EMAIL_PROVIDER=GMAIL
SMTP_ADDRESS=smtp.gmail.com
SMTP_PORT=587
SMTP_FROM_NAME=Support Team

# Harvester settings
HARVESTER_LOG=/var/www/harvester/

# Metasploit settings
METASPLOIT_PATH=/opt/metasploit-framework/
AUTO_MIGRATE=ON
```

---

## Workflow Operativo

1. **Pianificazione**: Definisci obiettivi e scope del test
2. **Ricognizione**: Raccogli informazioni sui target (OSINT)
3. **Preparazione**: Crea template email e siti clone convincenti
4. **Esecuzione**: Lancia la campagna in modo controllato
5. **Monitoraggio**: Traccia le interazioni e le credenziali raccolte
6. **Analisi**: Valuta il tasso di successo
7. **Report**: Documenta risultati e raccomandazioni

---

## Best Practices

- **Autorizzazione**: Ottieni sempre permesso scritto dal management
- **Scope limitato**: Definisci chiaramente i target e i limiti
- **Realismo controllato**: Crea scenari realistici ma non dannosi
- **Privacy**: Gestisci le credenziali raccolte in modo sicuro e cancellale dopo il test
- **Feedback positivo**: Usa i risultati per training, non per punire
- **Documentazione**: Mantieni log dettagliati di tutte le attività
- **Legal compliance**: Verifica la conformità con le normative locali (GDPR, ecc.)

## Riferimenti

- [SET GitHub Repository](https://github.com/trustedsec/social-engineer-toolkit)
- [TrustedSec - SET Documentation](https://www.trustedsec.com/tools/the-social-engineer-toolkit-set/)
- [Social Engineering Playbook](https://www.social-engineer.org/)
- [OWASP Testing Guide - Social Engineering](https://owasp.org/www-project-web-security-testing-guide/)
