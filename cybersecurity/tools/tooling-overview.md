# Tooling Overview

## Scopo

Questa guida fornisce una panoramica completa dei tool essenziali per penetration testing e security assessment, organizzati per categoria d'uso.

## Prerequisiti

- Kali Linux o distribuzione security
- Conoscenza base networking
- Comprensione metodologie testing
- **Autorizzazione per testing**

---

## Reconnaissance

### Passive

| Tool | Uso |
|------|-----|
| theHarvester | Email, subdomain enumeration |
| Maltego | OSINT visualization |
| Shodan | Internet-exposed devices |
| Censys | Certificate, host search |
| Recon-ng | OSINT framework |
| SpiderFoot | Automated OSINT |
| FOCA | Metadata extraction |

### Active

| Tool | Uso |
|------|-----|
| Nmap | Port scanning, service detection |
| Masscan | Fast port scanning |
| Rustscan | Fast Nmap wrapper |
| Nikto | Web vulnerability scanner |
| WhatWeb | Web technology fingerprint |
| Wappalyzer | Technology detection |

---

## Vulnerability Scanning

| Tool | Uso |
|------|-----|
| Nessus | Comprehensive vuln scanner |
| OpenVAS | Open source scanner |
| Nuclei | Template-based scanner |
| Qualys | Enterprise scanning |
| Acunetix | Web application scanner |
| Burp Suite Pro | Web app security |

---

## Web Application

### Analysis

| Tool | Uso |
|------|-----|
| Burp Suite | Proxy, scanner, intruder |
| OWASP ZAP | Open source proxy |
| Caido | Modern web proxy |
| mitmproxy | CLI proxy |
| Fiddler | Windows proxy |

### Exploitation

| Tool | Uso |
|------|-----|
| SQLmap | SQL injection automation |
| Commix | Command injection |
| XSStrike | XSS detection |
| NoSQLMap | NoSQL injection |
| Wfuzz | Web fuzzer |
| Ffuf | Fast fuzzer |
| Gobuster | Directory brute force |
| Feroxbuster | Recursive brute force |

---

## Network

### Sniffing

| Tool | Uso |
|------|-----|
| Wireshark | Packet analysis |
| Tcpdump | CLI packet capture |
| TShark | CLI Wireshark |
| NetworkMiner | Forensic analysis |

### MITM

| Tool | Uso |
|------|-----|
| Bettercap | Network attacks |
| Ettercap | ARP spoofing |
| Responder | LLMNR/NBT-NS poisoning |
| mitm6 | IPv6 attacks |

---

## Password

### Cracking

| Tool | Uso |
|------|-----|
| Hashcat | GPU cracking |
| John the Ripper | CPU cracking |
| Hydra | Online brute force |
| Medusa | Parallel brute force |
| CrackStation | Online lookup |

### Analysis

| Tool | Uso |
|------|-----|
| Mimikatz | Windows credential extraction |
| secretsdump.py | Remote credential dump |
| LaZagne | Local credential recovery |
| CrackMapExec | SMB credential testing |

---

## Exploitation

### Frameworks

| Tool | Uso |
|------|-----|
| Metasploit | Exploit framework |
| Cobalt Strike | Red team operations |
| Sliver | C2 framework |
| Empire | PowerShell/Python |
| Havoc | Modern C2 |

### Specifici

| Tool | Uso |
|------|-----|
| SearchSploit | Exploit database search |
| ExploitDB | Vulnerability database |
| Pwntools | CTF/exploit dev |
| ROPgadget | ROP chain building |

---

## Evasion

| Tool | Uso |
|------|-----|
| Veil | Payload obfuscation |
| Tor | Anonymous routing |
| Proxychains | Traffic proxying |
| DNSCat2 | DNS tunneling |
| Iodine | DNS tunnel |
| dns2tcp | DNS tunnel |

---

## Security Distros

| Distro | Focus |
|--------|-------|
| Kali Linux | Penetration testing |
| Parrot OS | Security e privacy |
| BlackArch | Arch-based security |

---

## Post-Exploitation

### Enumeration

| Tool | Uso |
|------|-----|
| LinPEAS | Linux privilege escalation |
| WinPEAS | Windows privilege escalation |
| BloodHound | AD attack paths |
| PowerView | AD enumeration |
| ADRecon | AD reconnaissance |

### Pivoting

| Tool | Uso |
|------|-----|
| Chisel | TCP tunneling |
| Ligolo-ng | Tunneling |
| SSHuttle | VPN over SSH |
| Proxychains | SOCKS proxy |

---

## Wireless

| Tool | Uso |
|------|-----|
| Aircrack-ng | WiFi cracking suite |
| Bettercap | WiFi attacks |
| Kismet | Wireless detector |
| Wifite | Automated attacks |
| Fluxion | Evil twin |
| Fern | WiFi auditing GUI |

---

## Cloud

| Tool | Uso |
|------|-----|
| ScoutSuite | Multi-cloud audit |
| Prowler | AWS security |
| Pacu | AWS exploitation |
| CloudMapper | AWS visualization |
| AzureHound | Azure enumeration |
| GCPBucketBrute | GCP bucket enum |

---

## Mobile

| Tool | Uso |
|------|-----|
| MobSF | Mobile security framework |
| Frida | Dynamic instrumentation |
| Objection | Runtime exploration |
| jadx | Java decompiler |
| APKTool | APK reverse engineering |
| Hopper | iOS disassembler |

---

## Container

| Tool | Uso |
|------|-----|
| Trivy | Vulnerability scanner |
| Grype | Container scanning |
| kube-hunter | K8s penetration |
| kube-bench | CIS benchmark |
| Falco | Runtime security |
| Docker Bench | Docker CIS |

---

## Forensics

| Tool | Uso |
|------|-----|
| Autopsy | Disk forensics |
| Volatility | Memory forensics |
| FTK Imager | Disk imaging |
| Sleuth Kit | File analysis |
| Binwalk | Firmware analysis |
| Foremost | File carving |

---

## Reporting

| Tool | Uso |
|------|-----|
| Dradis | Collaborative reporting |
| PlexTrac | Enterprise platform |
| SysReptor | Open source |
| CherryTree | Note taking |
| Obsidian | Knowledge base |

---

## Distributions

| Distro | Focus |
|--------|-------|
| Kali Linux | Penetration testing |
| Parrot Security | Security/privacy |
| BlackArch | Arch-based security |
| Commando VM | Windows security |
| REMnux | Malware analysis |

---

## Installation Base

```bash
# Kali metapackages
apt install kali-linux-default
apt install kali-tools-web
apt install kali-tools-top10

# Docker tools
docker pull owasp/zap2docker-stable
docker pull nmap

# Python tools
pip install impacket
pip install pwntools
```

---

## Best Practices

- **Updates**: Mantieni tool aggiornati
- **Documentation**: Leggi documentazione
- **Lab**: Pratica in ambiente controllato
- **Legal**: Usa solo con autorizzazione
- **Logging**: Documenta attività

## Riferimenti

- [Kali Tools](https://www.kali.org/tools/)
- [SecTools](https://sectools.org/)
- [Awesome Hacking](https://github.com/Hack-with-Github/Awesome-Hacking)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
