# Forensics Tools

## Scopo

Questa guida copre tool e tecniche di digital forensics per acquisizione, analisi e investigazione di sistemi compromessi.

## Prerequisiti

- Conoscenza file system
- Forensics workstation
- Chain of custody awareness
- **Autorizzazione legale**

---

## Disk Forensics

### Acquisizione

#### FTK Imager

```
1. Download da AccessData
2. Crea forensic image:
   - File > Create Disk Image
   - Select Source (Physical/Logical)
   - Select Destination (E01/DD)
   - Verify hash after imaging
```

#### dd/dcfldd

```bash
# dd base
dd if=/dev/sda of=image.dd bs=4M status=progress

# dcfldd con hash
dcfldd if=/dev/sda of=image.dd hash=sha256 hashlog=hash.txt

# Con compressione
dd if=/dev/sda | gzip > image.dd.gz

# Verificare hash
sha256sum image.dd
```

#### Guymager

```bash
# GUI imaging tool
apt install guymager
guymager

# Supporta E01, EWF, AFF
```

### Analisi

#### Autopsy

```bash
# Installazione
apt install autopsy

# Avvio
autopsy

# Funzionalità:
# - Timeline analysis
# - Keyword search
# - Hash lookup
# - File carving
# - Web artifacts
```

#### Sleuth Kit

```bash
# File system info
fsstat image.dd

# Lista file
fls -r image.dd

# Visualizza file
icat image.dd INODE_NUMBER > extracted_file

# Timeline
fls -r -m / image.dd > bodyfile
mactime -b bodyfile > timeline.txt

# Deleted files
fls -d image.dd
```

### File Carving

#### Foremost

```bash
# Install
apt install foremost

# Carve
foremost -t all -i image.dd -o output/

# Tipi specifici
foremost -t jpg,pdf,doc -i image.dd
```

#### Scalpel

```bash
# Configura /etc/scalpel/scalpel.conf
# Uncomment file types

# Run
scalpel -c /etc/scalpel/scalpel.conf image.dd -o output/
```

#### PhotoRec

```bash
# Incluso con testdisk
photorec image.dd

# Interactive recovery
```

---

## Memory Forensics

### Acquisizione

#### LiME (Linux)

```bash
# Compile module
git clone https://github.com/504ensicsLabs/LiME
cd LiME/src
make

# Dump
insmod lime.ko "path=/mnt/usb/memory.lime format=lime"
```

#### WinPMEM

```
# Windows memory dump
winpmem.exe memory.raw

# Con pagefile
winpmem.exe --pagefile memory.raw
```

#### DumpIt

```
# Semplice - double click
DumpIt.exe
# Crea dump in directory corrente
```

### Analisi con Volatility

```bash
# Volatility 2
volatility -f memory.dmp imageinfo
volatility -f memory.dmp --profile=Win10x64 pslist
volatility -f memory.dmp --profile=Win10x64 pstree
volatility -f memory.dmp --profile=Win10x64 netscan
volatility -f memory.dmp --profile=Win10x64 filescan
volatility -f memory.dmp --profile=Win10x64 dumpfiles -Q 0xOFFSET -D output/

# Volatility 3
python vol.py -f memory.dmp windows.info
python vol.py -f memory.dmp windows.pslist
python vol.py -f memory.dmp windows.pstree
python vol.py -f memory.dmp windows.netscan
python vol.py -f memory.dmp windows.filescan
python vol.py -f memory.dmp windows.malfind
python vol.py -f memory.dmp windows.hashdump
```

#### Plugin Comuni

| Plugin | Uso |
|--------|-----|
| pslist/pstree | Lista processi |
| netscan | Connessioni rete |
| malfind | Code injection |
| filescan | File handles |
| dumpfiles | Estrai file |
| hashdump | Password hashes |
| cmdline | Comandi eseguiti |
| consoles | Console output |
| hivelist | Registry hives |

---

## Log Analysis

### Linux Logs

```bash
# Auth log
cat /var/log/auth.log | grep -i "failed\|accepted"

# Syslog
cat /var/log/syslog

# Journal
journalctl --since "2024-01-01" --until "2024-01-02"

# Apache
cat /var/log/apache2/access.log | awk '{print $1}' | sort | uniq -c | sort -rn
```

### Windows Event Logs

```powershell
# Security log
Get-WinEvent -LogName Security -MaxEvents 100

# Filter by ID
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624,4625}

# Export
wevtutil epl Security security.evtx
```

| Event ID | Descrizione |
|----------|-------------|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4720 | User created |
| 4722 | User enabled |
| 4732 | User added to group |
| 7045 | Service installed |

---

## Network Forensics

### Packet Analysis

```bash
# Wireshark
wireshark capture.pcap

# TShark
tshark -r capture.pcap -Y "http.request"
tshark -r capture.pcap -T fields -e ip.src -e ip.dst

# Estrai file
tshark -r capture.pcap --export-objects http,output/
```

### NetworkMiner

```
# Windows GUI
# Automatic extraction:
# - Files
# - Images
# - Credentials
# - DNS queries
```

---

## Malware Analysis

### Static

```bash
# File info
file malware.exe
strings malware.exe | less
strings -el malware.exe  # Unicode

# Hash
md5sum malware.exe
sha256sum malware.exe

# PE analysis
peframe malware.exe
pefile
```

### Dynamic

```bash
# Sandbox
# Any.Run
# Hybrid Analysis
# Joe Sandbox
# VirusTotal

# DIY sandbox
# Windows VM isolata
# Process Monitor
# Wireshark
```

### YARA

```bash
# Scan con rules
yara rules.yar malware.exe

# Rule example
rule suspicious_string {
    strings:
        $a = "cmd.exe" nocase
        $b = "powershell" nocase
    condition:
        any of them
}
```

---

## Timeline Analysis

### Plaso/log2timeline

```bash
# Crea timeline
log2timeline.py timeline.plaso image.dd

# Estrai
psort.py -o l2tcsv timeline.plaso > timeline.csv

# Filtra
psort.py -w timeline.csv timeline.plaso "date > '2024-01-01'"
```

### TimeSketch

```bash
# Web-based timeline analysis
# Import plaso file
# Collaborative analysis
```

---

## Browser Forensics

### Artifacts

| Browser | Location |
|---------|----------|
| Chrome | %LocalAppData%\Google\Chrome\User Data |
| Firefox | %AppData%\Mozilla\Firefox\Profiles |
| Edge | %LocalAppData%\Microsoft\Edge\User Data |

### Hindsight (Chrome)

```bash
# Chrome forensics
pip install pyhindsight
hindsight.py -i "C:\Users\USER\AppData\Local\Google\Chrome\User Data" -o output
```

---

## Mobile Forensics

| Tool | Uso |
|------|-----|
| Cellebrite | Commercial, comprehensive |
| Oxygen | Commercial |
| UFED | Physical extraction |
| ADB | Android logical |
| libimobiledevice | iOS |

---

## Tools Summary

| Category | Tools |
|----------|-------|
| Imaging | FTK Imager, dd, Guymager |
| Disk Analysis | Autopsy, Sleuth Kit |
| Memory | Volatility, LiME, WinPMEM |
| Carving | Foremost, Scalpel, PhotoRec |
| Network | Wireshark, NetworkMiner |
| Timeline | Plaso, TimeSketch |
| Malware | YARA, PEframe, Cuckoo |

---

## Best Practices

- **Chain of custody**: Documenta tutto
- **Write blockers**: Usa sempre
- **Hashing**: Verifica integrità
- **Documentation**: Log dettagliato
- **Validation**: Tool validation

## Riferimenti

- [SANS DFIR](https://www.sans.org/digital-forensics-incident-response/)
- [Volatility](https://volatilityfoundation.org/)
- [Autopsy](https://www.autopsy.com/)
- [NIST Forensics](https://www.nist.gov/itl/ssd/software-quality-group/computer-forensics-tool-testing-program-cftt)
