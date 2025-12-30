# Asterisk - VoIP Spoofing Lab

## Scopo

Questa guida descrive come configurare Asterisk PBX per creare un ambiente di laboratorio controllato per testing di caller ID spoofing. Asterisk permette di simulare scenari di vishing in modo sicuro e controllato.

## Prerequisiti

- Server Linux (Debian/Ubuntu consigliato)
- Asterisk PBX installato
- Trunk SIP (opzionale, per chiamate esterne)
- Conoscenza base di VoIP e SIP
- **Ambiente di lab isolato**
- **Autorizzazione per test su rete pubblica**

## Installazione

### Debian/Ubuntu

```bash
# Aggiorna sistema
sudo apt-get update
sudo apt-get upgrade

# Installa dipendenze
sudo apt-get install build-essential wget libssl-dev libncurses5-dev \
    libnewt-dev libxml2-dev linux-headers-$(uname -r) libsqlite3-dev \
    uuid-dev libjansson-dev

# Scarica Asterisk
cd /usr/src
sudo wget https://downloads.asterisk.org/pub/telephony/asterisk/asterisk-20-current.tar.gz
sudo tar xvf asterisk-20-current.tar.gz
cd asterisk-20*/

# Compila e installa
sudo ./configure
sudo make menuselect  # Seleziona moduli
sudo make
sudo make install
sudo make samples
sudo make config

# Avvia Asterisk
sudo systemctl start asterisk
sudo systemctl enable asterisk
```

### Verifica Installazione

```bash
# Accedi alla CLI
sudo asterisk -rvvv

# Verifica versione
CLI> core show version

# Verifica moduli
CLI> module show
```

---

## Configurazione Base

### sip.conf - Configurazione SIP

```ini
; /etc/asterisk/sip.conf

[general]
context=default
allowguest=no
allowoverlap=no
bindport=5060
bindaddr=0.0.0.0
srvlookup=yes
disallow=all
allow=ulaw
allow=alaw
allow=gsm

; Extension interna per testing
[1001]
type=friend
host=dynamic
secret=password1001
context=internal
callerid="Test User 1" <1001>

[1002]
type=friend
host=dynamic
secret=password1002
context=internal
callerid="Test User 2" <1002>

; Trunk SIP (per chiamate esterne)
[sip-trunk]
type=peer
host=sip.provider.com
username=account_id
secret=trunk_password
fromuser=account_id
fromdomain=sip.provider.com
context=from-trunk
insecure=invite,port
```

### extensions.conf - Dialplan

```ini
; /etc/asterisk/extensions.conf

[general]
static=yes
writeprotect=no

[internal]
; Chiamate interne
exten => _1XXX,1,NoOp(Chiamata interna a ${EXTEN})
exten => _1XXX,n,Dial(SIP/${EXTEN},30)
exten => _1XXX,n,Hangup()

; Caller ID Spoofing - SOLO PER LAB
[spoof-lab]
; Spoof caller ID su chiamata interna
exten => _2XXX,1,NoOp(Spoof Call to ${EXTEN})
exten => _2XXX,n,Set(CALLERID(num)=${SPOOF_NUMBER})
exten => _2XXX,n,Set(CALLERID(name)=${SPOOF_NAME})
exten => _2XXX,n,Dial(SIP/${EXTEN:1},30)
exten => _2XXX,n,Hangup()

; Menu interattivo per spoofing
exten => 999,1,Answer()
exten => 999,n,Read(SPOOF_NUMBER,enter-phone-number,11)
exten => 999,n,Read(DEST_NUMBER,enter-destination,11)
exten => 999,n,Set(CALLERID(num)=${SPOOF_NUMBER})
exten => 999,n,Set(CALLERID(name)=Spoofed Call)
exten => 999,n,Dial(SIP/${DEST_NUMBER},30)
exten => 999,n,Hangup()

[from-trunk]
; Gestione chiamate in ingresso
exten => _X.,1,NoOp(Chiamata in ingresso da ${CALLERID(num)})
exten => _X.,n,Goto(internal,1001,1)
```

---

## Spoofing Caller ID

### Metodo 1: Dialplan Diretto

```ini
; In extensions.conf
exten => 100,1,Answer()
exten => 100,n,Set(CALLERID(num)=+390212345678)
exten => 100,n,Set(CALLERID(name)=Banca Italia)
exten => 100,n,Dial(SIP/1002,30)
exten => 100,n,Hangup()
```

### Metodo 2: AGI Script

```bash
#!/bin/bash
# /var/lib/asterisk/agi-bin/spoof.sh

#!/bin/bash
read -r input
while [[ "$input" != "" ]]; do
    read -r input
done

# Leggi variabili
SPOOF_NUM=$1
SPOOF_NAME=$2
DEST=$3

# Imposta caller ID
echo "SET CALLERID \"$SPOOF_NAME\" <$SPOOF_NUM>"
echo "EXEC Dial SIP/$DEST,30"
```

```ini
; In extensions.conf
exten => 101,1,Answer()
exten => 101,n,AGI(spoof.sh,+390212345678,"Banca Italia",1002)
exten => 101,n,Hangup()
```

### Metodo 3: Modifica SIP Headers

```ini
; In extensions.conf
exten => 102,1,Answer()
exten => 102,n,SIPAddHeader(P-Asserted-Identity: <sip:+390212345678@domain.com>)
exten => 102,n,SIPAddHeader(Remote-Party-ID: "+390212345678" <sip:+390212345678@domain.com>;party=calling)
exten => 102,n,Dial(SIP/trunk/destinazione)
exten => 102,n,Hangup()
```

---

## Configurazione Trunk SIP

### Per Chiamate Esterne

```ini
; /etc/asterisk/sip.conf

[trunk-provider]
type=peer
host=sip.provider.com
username=account
fromuser=account
secret=password
context=from-trunk
disallow=all
allow=ulaw
trustrpid=yes
sendrpid=yes
```

```ini
; /etc/asterisk/extensions.conf

[outbound-spoof]
exten => _0X.,1,NoOp(Outbound spoofed call)
exten => _0X.,n,Set(CALLERID(num)=+39XXXXXXXXXX)
exten => _0X.,n,Set(CALLERID(name)=Custom Name)
exten => _0X.,n,Dial(SIP/trunk-provider/${EXTEN})
exten => _0X.,n,Hangup()
```

---

## Scenari di Test

### Scenario 1: Vishing Simulation

```ini
[vishing-test]
; Simula chiamata da helpdesk IT
exten => 500,1,Answer()
exten => 500,n,Set(CALLERID(num)=+39026789000)  ; Numero IT Helpdesk
exten => 500,n,Set(CALLERID(name)=IT Helpdesk)
exten => 500,n,Playback(custom/it-helpdesk-intro)
exten => 500,n,Dial(SIP/${TARGET_EXT},60)
exten => 500,n,Hangup()
```

### Scenario 2: CEO Fraud Test

```ini
[ceo-fraud-test]
; Simula chiamata da CEO
exten => 501,1,Answer()
exten => 501,n,Set(CALLERID(num)=+39XXXXXXXXXX)  ; Numero CEO
exten => 501,n,Set(CALLERID(name)=Mario Rossi CEO)
exten => 501,n,Dial(SIP/1002,60)
exten => 501,n,Hangup()
```

---

## Logging e Monitoring

### Abilita Logging

```ini
; /etc/asterisk/logger.conf

[general]
dateformat=%F %T

[logfiles]
console => notice,warning,error
messages => notice,warning,error
full => notice,warning,error,debug,verbose
cdr => cdr
```

### CDR (Call Detail Records)

```ini
; /etc/asterisk/cdr.conf

[general]
enable=yes
unanswered=yes

[csv]
usegmtime=yes
loguniqueid=yes
loguserfield=yes
```

### Verifica Log

```bash
# Log in tempo reale
sudo tail -f /var/log/asterisk/full

# CDR
sudo cat /var/log/asterisk/cdr-csv/Master.csv
```

---

## Sicurezza

### Hardening Asterisk

```ini
; sip.conf
[general]
alwaysauthreject=yes
allowguest=no

; Limita IP
deny=0.0.0.0/0.0.0.0
permit=192.168.1.0/255.255.255.0
```

### Firewall

```bash
# Permetti solo IP autorizzati
sudo iptables -A INPUT -p udp --dport 5060 -s 192.168.1.0/24 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 5060 -j DROP
sudo iptables -A INPUT -p udp --dport 10000:20000 -s 192.168.1.0/24 -j ACCEPT
```

---

## Best Practices

- **Ambiente isolato**: Usa sempre una rete di lab separata
- **Autorizzazione**: Mai testare su numeri esterni senza permesso
- **Logging**: Mantieni log completi di tutte le chiamate
- **Accesso ristretto**: Limita chi può usare il sistema
- **Cleanup**: Rimuovi configurazioni di test dopo l'uso
- **Compliance**: Verifica normative telecomunicazioni locali
- **Documentazione**: Documenta tutte le configurazioni

## Riferimenti

- [Asterisk Documentation](https://wiki.asterisk.org/)
- [Asterisk: The Definitive Guide](https://www.asteriskdocs.org/)
- [VoIP Security](https://www.voip-info.org/wiki/view/VoIP+Security)
- [FreePBX](https://www.freepbx.org/) - GUI per Asterisk
