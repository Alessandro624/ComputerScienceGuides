# SSH

## Scopo

Questa guida fornisce una panoramica di SSH (Secure Shell), il protocollo per connessioni remote sicure, autenticazione e trasferimento file.

## Prerequisiti

- Terminale (Linux/macOS/Windows con OpenSSH)
- Conoscenza base networking

---

## Comandi Base

### Connessione

```bash
# Connessione base
ssh user@hostname

# Porta specifica
ssh -p 2222 user@hostname

# Con chiave specifica
ssh -i ~/.ssh/mykey user@hostname

# Verbose (debug)
ssh -v user@hostname
ssh -vv user@hostname  # Piu verbose
```

### Esecuzione Comandi Remoti

```bash
# Comando singolo
ssh user@host "ls -la"

# Comandi multipli
ssh user@host "cd /var/log && tail -100 syslog"

# Script locale su host remoto
ssh user@host < script.sh

# Con variabili
ssh user@host "echo \$HOME"
```

---

## Gestione Chiavi

### Generazione

```bash
# RSA (4096 bit)
ssh-keygen -t rsa -b 4096 -C "email@example.com"

# Ed25519 (consigliato)
ssh-keygen -t ed25519 -C "email@example.com"

# Con nome specifico
ssh-keygen -t ed25519 -f ~/.ssh/mykey -C "comment"

# Senza passphrase (non consigliato)
ssh-keygen -t ed25519 -N "" -f ~/.ssh/mykey
```

### File Generati

```
~/.ssh/
├── id_ed25519          # Chiave privata
├── id_ed25519.pub      # Chiave pubblica
├── known_hosts         # Host conosciuti
├── authorized_keys     # Chiavi autorizzate (server)
└── config              # Configurazione client
```

### Copia Chiave su Server

```bash
# Metodo consigliato
ssh-copy-id user@hostname

# Con chiave specifica
ssh-copy-id -i ~/.ssh/mykey.pub user@hostname

# Manuale
cat ~/.ssh/id_ed25519.pub | ssh user@host "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys"
```

### Gestione Chiavi

```bash
# Lista chiavi nell'agent
ssh-add -l

# Aggiungi chiave
ssh-add ~/.ssh/mykey

# Rimuovi tutte le chiavi
ssh-add -D

# Avvia agent
eval "$(ssh-agent -s)"
```

---

## File Config

### ~/.ssh/config

```
# Host specifico
Host myserver
    HostName server.example.com
    User admin
    Port 2222
    IdentityFile ~/.ssh/mykey

# Con jump host
Host internal
    HostName 10.0.0.5
    User admin
    ProxyJump jumphost

# Jump host
Host jumphost
    HostName jump.example.com
    User jump

# GitHub
Host github.com
    HostName github.com
    User git
    IdentityFile ~/.ssh/github_key

# Wildcard
Host *.example.com
    User admin
    IdentityFile ~/.ssh/company_key

# Defaults
Host *
    ServerAliveInterval 60
    ServerAliveCountMax 3
    AddKeysToAgent yes
```

### Uso Config

```bash
# Invece di: ssh -i ~/.ssh/mykey -p 2222 admin@server.example.com
ssh myserver

# Invece di: ssh -J jump.example.com admin@10.0.0.5
ssh internal
```

---

## Trasferimento File

### SCP

```bash
# Upload file
scp file.txt user@host:/path/to/dest/

# Download file
scp user@host:/path/file.txt ./local/

# Directory (ricorsivo)
scp -r folder/ user@host:/path/

# Preserva attributi
scp -p file.txt user@host:/path/

# Porta specifica
scp -P 2222 file.txt user@host:/path/

# Tra host remoti
scp user1@host1:/file user2@host2:/path/
```

### SFTP

```bash
# Connessione
sftp user@host

# Comandi SFTP
sftp> pwd           # Directory remota
sftp> lpwd          # Directory locale
sftp> ls            # Lista remota
sftp> lls           # Lista locale
sftp> cd /path      # Cambia dir remota
sftp> lcd /local    # Cambia dir locale
sftp> get file.txt  # Download
sftp> put file.txt  # Upload
sftp> mget *.txt    # Download multipli
sftp> mput *.txt    # Upload multipli
sftp> rm file       # Rimuovi
sftp> mkdir dir     # Crea directory
sftp> exit          # Esci
```

### Rsync over SSH

```bash
# Sync locale -> remoto
rsync -avz ./folder/ user@host:/path/

# Sync remoto -> locale
rsync -avz user@host:/path/ ./local/

# Con progress
rsync -avzP ./folder/ user@host:/path/

# Delete extra files
rsync -avz --delete ./folder/ user@host:/path/

# Exclude
rsync -avz --exclude='*.log' ./folder/ user@host:/path/
```

---

## Port Forwarding

### Local Port Forwarding

```bash
# Accedi a servizio remoto localmente
# localhost:8080 -> remotehost:80
ssh -L 8080:localhost:80 user@host

# Accedi a DB remoto
ssh -L 3306:dbserver:3306 user@jumphost

# Background
ssh -fNL 8080:localhost:80 user@host
```

### Remote Port Forwarding

```bash
# Esponi servizio locale al remoto
# remotehost:8080 -> localhost:3000
ssh -R 8080:localhost:3000 user@host
```

### Dynamic Port Forwarding (SOCKS)

```bash
# Crea SOCKS proxy
ssh -D 1080 user@host

# Background
ssh -fND 1080 user@host
```

### Tunnel Persistente

```bash
# Con autoreconnect (autossh)
autossh -M 0 -fNL 8080:localhost:80 user@host
```

---

## Jump Host / Bastion

```bash
# Vecchio metodo
ssh -J user@jump user@internal

# Multipli jump
ssh -J user@jump1,user@jump2 user@internal

# Config file
Host internal
    ProxyJump jumphost
```

---

## Sicurezza Server

### /etc/ssh/sshd_config

```
# Porta non standard
Port 2222

# Disabilita root login
PermitRootLogin no

# Solo chiavi, no password
PasswordAuthentication no
PubkeyAuthentication yes

# Limita utenti
AllowUsers admin deploy

# Limita gruppi
AllowGroups sshusers

# Timeout
ClientAliveInterval 300
ClientAliveCountMax 2

# Limita tentativi
MaxAuthTries 3

# Disabilita X11 forwarding
X11Forwarding no
```

### Applica Modifiche

```bash
# Testa configurazione
sshd -t

# Riavvia servizio
sudo systemctl restart sshd
```

---

## Troubleshooting

### Permessi

```bash
# Directory .ssh
chmod 700 ~/.ssh

# Chiave privata
chmod 600 ~/.ssh/id_ed25519

# Chiave pubblica
chmod 644 ~/.ssh/id_ed25519.pub

# authorized_keys
chmod 600 ~/.ssh/authorized_keys

# config
chmod 600 ~/.ssh/config
```

### Debug

```bash
# Client verbose
ssh -vvv user@host

# Server log
sudo tail -f /var/log/auth.log
journalctl -u sshd -f
```

### Known Hosts

```bash
# Rimuovi entry
ssh-keygen -R hostname

# Aggiungi manualmente
ssh-keyscan hostname >> ~/.ssh/known_hosts
```

---

## Best Practices

- **Chiavi Ed25519**: Preferisci Ed25519 a RSA
- **Passphrase**: Proteggi chiavi con passphrase
- **No Root**: Disabilita login root
- **No Password**: Usa solo autenticazione a chiave
- **Fail2ban**: Proteggi da brute force
- **Porta**: Considera porta non standard

## Riferimenti

- [OpenSSH Manual](https://www.openssh.com/manual.html)
- [SSH Academy](https://www.ssh.com/academy/ssh)
- [DigitalOcean SSH Tutorial](https://www.digitalocean.com/community/tutorials/ssh-essentials-working-with-ssh-servers-clients-and-keys)
