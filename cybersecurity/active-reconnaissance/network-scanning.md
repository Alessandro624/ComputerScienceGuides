# Network Scanning

## Scopo

Questa guida copre le tecniche e gli strumenti per la scansione attiva delle reti, permettendo di identificare host attivi, porte aperte, servizi in esecuzione e sistemi operativi. La scansione di rete è una fase fondamentale del penetration testing.

## Prerequisiti

- Kali Linux o distribuzione con strumenti di pentesting
- Nmap >= 7.0
- Permessi di root/sudo per scansioni avanzate
- **Autorizzazione scritta** per testare la rete target

## Installazione

```bash
# Debian/Ubuntu
sudo apt-get update
sudo apt-get install nmap masscan

# Verifica installazione
nmap --version
```

---

## Strumenti Principali

### Nmap

Nmap è lo scanner di rete più versatile e diffuso.

### Masscan

Scanner ad alta velocità per reti di grandi dimensioni.

### Rustscan

Scanner veloce scritto in Rust che si integra con nmap.

---

## Tecniche di Scansione con Nmap

### Host Discovery

```bash
# Ping sweep (ICMP echo)
nmap -sn 192.168.1.0/24

# Scansione ARP (rete locale)
nmap -sn -PR 192.168.1.0/24

# Senza ping (assume host attivi)
nmap -Pn 192.168.1.1

# Discovery con TCP SYN su porta 443
nmap -PS443 192.168.1.0/24

# Discovery con UDP
nmap -PU53 192.168.1.0/24
```

### Scansione Porte

```bash
# Scansione TCP SYN (stealth)
sudo nmap -sS 192.168.1.1

# Scansione TCP Connect
nmap -sT 192.168.1.1

# Scansione UDP
sudo nmap -sU 192.168.1.1

# Scansione tutte le porte
nmap -p- 192.168.1.1

# Scansione porte specifiche
nmap -p 22,80,443,8080 192.168.1.1

# Scansione range di porte
nmap -p 1-1000 192.168.1.1

# Top 100 porte più comuni
nmap --top-ports 100 192.168.1.1
```

### Rilevamento Servizi e Versioni

```bash
# Rilevamento versioni servizi
nmap -sV 192.168.1.1

# Versioni con intensità aggressiva
nmap -sV --version-intensity 5 192.168.1.1

# Rilevamento OS
sudo nmap -O 192.168.1.1

# Scansione completa (versioni + OS + script)
sudo nmap -A 192.168.1.1
```

### Nmap Scripting Engine (NSE)

```bash
# Esegui script di default
nmap -sC 192.168.1.1

# Script specifico
nmap --script=http-title 192.168.1.1

# Categoria di script
nmap --script=vuln 192.168.1.1

# Script multipli
nmap --script=http-enum,http-headers 192.168.1.1

# Elenco script disponibili
ls /usr/share/nmap/scripts/
```

### Scansioni Avanzate

```bash
# Scansione FIN (evasione firewall)
sudo nmap -sF 192.168.1.1

# Scansione NULL
sudo nmap -sN 192.168.1.1

# Scansione XMAS
sudo nmap -sX 192.168.1.1

# Idle scan (zombie)
sudo nmap -sI zombie_host target_host

# Decoy scan
sudo nmap -D decoy1,decoy2,ME target_host
```

### Timing e Performance

```bash
# Timing templates (0-5, più alto = più veloce)
nmap -T4 192.168.1.1

# Parallelismo
nmap --min-parallelism 100 192.168.1.0/24

# Rate limiting
nmap --max-rate 1000 192.168.1.0/24
```

### Output

```bash
# Output normale
nmap -oN scan.txt 192.168.1.1

# Output XML
nmap -oX scan.xml 192.168.1.1

# Output grepable
nmap -oG scan.gnmap 192.168.1.1

# Tutti i formati
nmap -oA scan 192.168.1.1
```

---

## Masscan

```bash
# Scansione veloce
sudo masscan 192.168.1.0/24 -p80,443 --rate=1000

# Scansione tutte le porte
sudo masscan 192.168.1.0/24 -p0-65535 --rate=10000

# Output in formato nmap-compatibile
sudo masscan 192.168.1.0/24 -p80 -oL results.txt
```

---

## Rustscan

```bash
# Installazione
cargo install rustscan

# Scansione base (passa a nmap)
rustscan -a 192.168.1.1

# Con argomenti nmap
rustscan -a 192.168.1.1 -- -sV -sC
```

---

## Workflow Operativo

1. **Host Discovery**: Identifica host attivi nella rete
2. **Port Scanning**: Trova porte aperte sugli host
3. **Service Detection**: Identifica servizi e versioni
4. **OS Detection**: Determina i sistemi operativi
5. **Script Scanning**: Esegui script per vulnerabilità
6. **Documentazione**: Salva i risultati in formati multipli

---

## Best Practices

- **Autorizzazione**: Ottieni sempre permesso scritto prima di scansionare
- **Logging**: Mantieni log dettagliati di tutte le attività
- **Timing**: Usa timing appropriati per evitare di sovraccaricare la rete
- **Stealth**: Considera tecniche di evasione in ambienti con IDS/IPS
- **Verifica**: Conferma manualmente i risultati importanti
- **Scope**: Rispetta rigorosamente lo scope definito
- **Impatto**: Valuta l'impatto delle scansioni su sistemi di produzione

## Riferimenti

- [Nmap Official Documentation](https://nmap.org/docs.html)
- [Nmap Network Scanning Book](https://nmap.org/book/)
- [Masscan GitHub](https://github.com/robertdavidgraham/masscan)
- [Rustscan GitHub](https://github.com/RustScan/RustScan)
