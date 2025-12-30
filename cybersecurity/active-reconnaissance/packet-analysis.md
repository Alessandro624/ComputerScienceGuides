# Packet Analysis

## Scopo

Questa guida copre le tecniche di cattura e analisi del traffico di rete utilizzando tcpdump e Wireshark. L'analisi dei pacchetti è fondamentale per il debugging di rete, l'analisi forense e l'identificazione di attività malevole.

## Prerequisiti

- Privilegi root/sudo per cattura pacchetti
- Wireshark e/o tcpdump installati
- Interfaccia di rete configurata
- Conoscenza base di protocolli di rete (TCP/IP, HTTP, DNS)

## Installazione

```bash
# Debian/Ubuntu
sudo apt-get update
sudo apt-get install tcpdump wireshark tshark

# Permessi per cattura senza root
sudo usermod -aG wireshark $USER
```

---

## Tcpdump

### Cattura Base

```bash
# Cattura su interfaccia specifica
sudo tcpdump -i eth0

# Lista interfacce disponibili
sudo tcpdump -D

# Cattura con verbose
sudo tcpdump -v -i eth0

# Cattura N pacchetti
sudo tcpdump -c 100 -i eth0

# Salva su file
sudo tcpdump -w capture.pcap -i eth0

# Leggi da file
tcpdump -r capture.pcap
```

### Filtri

```bash
# Filtra per host
sudo tcpdump host 192.168.1.1

# Filtra per rete
sudo tcpdump net 192.168.1.0/24

# Filtra per porta
sudo tcpdump port 80

# Filtra per protocollo
sudo tcpdump tcp
sudo tcpdump udp
sudo tcpdump icmp

# Source/Destination
sudo tcpdump src host 192.168.1.1
sudo tcpdump dst port 443

# Combinazioni (AND, OR, NOT)
sudo tcpdump 'host 192.168.1.1 and port 80'
sudo tcpdump 'port 80 or port 443'
sudo tcpdump 'not port 22'
```

### Output Avanzato

```bash
# Mostra contenuto ASCII
sudo tcpdump -A -i eth0

# Mostra contenuto HEX e ASCII
sudo tcpdump -XX -i eth0

# Timestamp preciso
sudo tcpdump -tttt -i eth0

# Non risolvere nomi
sudo tcpdump -n -i eth0

# Non risolvere porte
sudo tcpdump -nn -i eth0

# Mostra pacchetti con dimensione
sudo tcpdump -e -i eth0
```

### Filtri Avanzati

```bash
# TCP flags (SYN)
sudo tcpdump 'tcp[tcpflags] & tcp-syn != 0'

# TCP flags (SYN-ACK)
sudo tcpdump 'tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)'

# HTTP GET requests
sudo tcpdump -A 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'

# Pacchetti più grandi di X bytes
sudo tcpdump 'greater 500'

# Pacchetti ICMP echo request
sudo tcpdump 'icmp[icmptype] == icmp-echo'
```

---

## Wireshark

### Filtri Display

```
# Filtra per IP
ip.addr == 192.168.1.1
ip.src == 192.168.1.1
ip.dst == 192.168.1.1

# Filtra per porta
tcp.port == 80
udp.port == 53

# Filtra per protocollo
http
dns
tcp
udp
icmp

# Combinazioni
ip.addr == 192.168.1.1 && tcp.port == 80
http || dns
!(tcp.port == 22)

# HTTP specifici
http.request.method == "GET"
http.request.method == "POST"
http.response.code == 200
http.response.code >= 400

# DNS
dns.qry.name contains "google"
dns.flags.response == 1

# TCP analysis
tcp.analysis.retransmission
tcp.analysis.duplicate_ack
tcp.analysis.zero_window
```

### Filtri Capture

```
# Cattura solo traffico HTTP
port 80

# Cattura solo da/verso un host
host 192.168.1.1

# Cattura range di porte
portrange 1-1024

# Escludi SSH
not port 22
```

### Statistiche Utili

- **Statistics > Conversations**: Mostra connessioni tra host
- **Statistics > Protocol Hierarchy**: Distribuzione protocolli
- **Statistics > Endpoints**: Lista endpoint
- **Statistics > IO Graphs**: Grafici traffico nel tempo
- **Analyze > Follow > TCP Stream**: Ricostruisce stream TCP

### Export

- **File > Export Objects > HTTP**: Estrae file trasferiti via HTTP
- **File > Export Specified Packets**: Esporta pacchetti selezionati

---

## TShark (CLI Wireshark)

```bash
# Cattura base
tshark -i eth0

# Salva su file
tshark -i eth0 -w capture.pcap

# Leggi file con filtro
tshark -r capture.pcap -Y "http"

# Estrai campi specifici
tshark -r capture.pcap -T fields -e ip.src -e ip.dst -e tcp.port

# Statistiche conversazioni
tshark -r capture.pcap -q -z conv,tcp

# Decodifica protocollo
tshark -r capture.pcap -d tcp.port==8080,http
```

---

## Analisi Specifica

### Analisi HTTP

```bash
# Estrai URL richieste
tshark -r capture.pcap -Y "http.request" -T fields -e http.host -e http.request.uri

# Estrai User-Agent
tshark -r capture.pcap -Y "http.request" -T fields -e http.user_agent

# Trova credenziali in chiaro
tshark -r capture.pcap -Y "http.request.method==POST" -T fields -e http.file_data
```

### Analisi DNS

```bash
# Query DNS
tshark -r capture.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name

# Risposte DNS
tshark -r capture.pcap -Y "dns.flags.response == 1" -T fields -e dns.qry.name -e dns.a
```

### Analisi TLS/SSL

```bash
# Handshake TLS
tshark -r capture.pcap -Y "ssl.handshake" -T fields -e ip.src -e ip.dst -e ssl.handshake.type

# Server Name (SNI)
tshark -r capture.pcap -Y "ssl.handshake.extension.type == 0" -T fields -e ssl.handshake.extensions_server_name
```

---

## Workflow Operativo

1. **Pianificazione**: Definisci cosa cercare e dove catturare
2. **Cattura**: Usa filtri appropriati per limitare il volume
3. **Filtraggio**: Applica filtri display per focus
4. **Analisi**: Esamina pattern, anomalie, contenuti
5. **Correlazione**: Collega eventi tra diversi stream
6. **Documentazione**: Esporta e documenta le evidenze

---

## Best Practices

- **Cattura minima**: Filtra alla source per ridurre il volume
- **Timestamp**: Usa clock sincronizzati (NTP) per correlazione
- **Storage**: Prevedi spazio sufficiente per catture lunghe
- **Privacy**: Rispetta normative sulla cattura del traffico
- **Integrità**: Calcola hash dei file pcap per chain of custody
- **Organizzazione**: Usa naming convention per i file di cattura

## Riferimenti

- [Wireshark Documentation](https://www.wireshark.org/docs/)
- [Tcpdump Manual](https://www.tcpdump.org/manpages/tcpdump.1.html)
- [Wireshark Display Filter Reference](https://www.wireshark.org/docs/dfref/)
- [PacketLife Cheat Sheets](https://packetlife.net/library/cheat-sheets/)
