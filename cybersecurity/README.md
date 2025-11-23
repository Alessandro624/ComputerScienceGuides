# Cybersecurity — Indice

Questa cartella contiene guidesu vari aspetti della sicurezza informatica.

## Passive Reconnaissance

- [OSINT](passive-reconnaissance/osint.md): raccolta di tecniche OSINT per trovare informazioni pubbliche su persone e organizzazioni.
- [DNS](passive-reconnaissance/dns.md): strumenti e comandi per l'analisi DNS (whois, dig, zone transfer, record lookup).
- [SSL Certificates](passive-reconnaissance/ssl-certificates.md): analisi dei certificati SSL/TLS per ricavare informazioni su servizi e domini.
- [Password Dumps](passive-reconnaissance/password-dumps.md): come cercare e valutare dump di password pubblici e mitigazioni.
- [File Metadata](passive-reconnaissance/file-metadata.md): estrazione metadati da documenti e immagini (EXIF, PDF metadata).
- [Search Engines](passive-reconnaissance/search-engines.md): tecniche avanzate di ricerca (Google dorking, motori specializzati).

## Active Reconnaissance

- [Network Scanning](active-reconnaissance/network-scanning.md): uso di `nmap` e strumenti di scansione per mappare reti e servizi.
- [Enumeration](active-reconnaissance/enumeration.md): tecniche di enumerazione di servizi, share, utenti e risorse.
- [Packet Analysis](active-reconnaissance/packet-analysis.md): analisi di traffico con `tcpdump` e Wireshark.

## Social Engineering

- [SET](social-engineering/set.md): panoramica di Social-Engineer Toolkit (SET) e scenari d'uso.
- [BeEF](social-engineering/beef.md): uso del framework BeEF per valutazioni di sicurezza lato browser.

## Call Spoofing

- [SpoofApp](call-spoofing/spoofapp.md): app e servizi per spoofing di chiamate (uso responsabile e limiti legali).
- [SpoofCard](call-spoofing/spoofcard.md): descrizione di servizi commerciali e contro-misure.
- [Asterisk](call-spoofing/asterisk.md): configurazioni Asterisk per testing in lab controllati.

## Network Vulnerabilities

- [Windows Resolution](network-vulns/windows-resolution.md): vulnerabilità legate a risoluzione e gestione dei nomi in ambienti Windows.
- [SMB](network-vulns/smb.md): attacchi e difese per SMB (enumerazione, exploitation, mitigazioni).
- [SNMP - SMTP](network-vulns/snmp-smtp.md): problemi comuni in SNMP e SMTP e come identificarli.
- [FTP](network-vulns/ftp.md): vulnerabilità e configurazioni insicure di server FTP.
- [Pass the Hash](network-vulns/pass-the-hash.md): spiegazione dell'attacco e contromisure.
- [Kerberos LDAP](network-vulns/kerberos-ldap.md): debolezze in Kerberos/LDAP e come eseguirne il testing.
- [On Path Attacks](network-vulns/on-path-attacks.md): attacchi on-path (ARP spoofing, DNS poisoning) e mitigazioni.
- [Route Manipulation](network-vulns/route-manipulation.md): manipolazione delle rotte e scenari di attacco.
- [DHCP Attacks](network-vulns/dhcp-attacks.md): attacchi e difese relativi a DHCP.

## Wireless Vulnerabilities

- [Evil Twin](wireless-vulns/evil-twin.md): creazione e rilevamento di Evil Twin AP.
- [Disassociation](wireless-vulns/disassociation.md): attacchi di disassociation e prevenzione.
- [PNL Attacks](wireless-vulns/pnl-attack.md): panoramica degli attacchi PNL (probe/notification/listener).
- [Jamming](wireless-vulns/jamming.md): tipi di jamming e limitazioni legali.
- [Wardriving](wireless-vulns/wardriving.md): tecniche e tool per mappare reti Wi‑Fi.
- [IV Attacks](wireless-vulns/iv-attack.md): attacchi contro cifrature legacy (IV reuse).
- [Karma](wireless-vulns/karma.md): exploit basati su client che cercano SSID noti.
- [Fragmentation](wireless-vulns/fragmentation.md): attacchi che sfruttano frammentazione dei pacchetti.
- [Credentials Harvesting](wireless-vulns/credentials-harvesting.md): raccolta credenziali da captive portals e attacchi correlati.
- [Bluetooth](wireless-vulns/bluetooth.md): attacchi su dispositivi Bluetooth.
- [RFID](wireless-vulns/rfid.md): vulnerabilità RFID e casi pratici.

## Application Vulnerabilities

- [Web Vulnerabilities](application-vulns/web-vulns.md): panoramica delle vulnerabilità web più comuni.
- [SQL Injection](application-vulns/sql-injection.md): esempi di SQLi e mitigazioni.
- [Command Injection](application-vulns/command-injection.md): come individuare e prevenire command injection.
- [Session Hijacking](application-vulns/session-hijacking.md): tecniche e contromisure per session hijack.
- [Password Tools](application-vulns/password-tools.md): strumenti per gestione e cracking di password (uso etico).
- [XSS - CSRF](application-vulns/xss-csrf.md): XSS e CSRF: esempi e difese.
- [LFI - RFI`](application-vulns/lfi-rfi.md): Local/Remote File Inclusion e mitigazioni.
- [Path Traversal](application-vulns/path-traversal.md): path traversal e controlli suggeriti.
- [API Security](application-vulns/api-security.md): sicurezza per API REST/GraphQL.
- [OWASP Testing](application-vulns/owasp-testing.md): riferimento alle metodologie OWASP per i test.

## Cloud Security

- [Credential Harvesting](cloud-security/credential-harvesting.md): focus su raccolta credenziali nelle piattaforme cloud.
- [Privilege Escalation](cloud-security/privilege-escalation.md): vettori di escalation privilegi in ambienti cloud.
- [Metadata Service](cloud-security/metadata-service.md): rischi legati alle metadata services (IMDS ecc.).
- [Misconfigurations](cloud-security/misconfigurations.md): esempi di misconfigurazioni comuni e come rilevarle.
- [Cloud Malware](cloud-security/cloud-malware.md): minacce specifiche per ambienti cloud.

## Mobile / IoT

- [Reverse Engineering](mobile-iot/reverse-engineering.md): tecniche di reverse engineering per app mobile e firmware.
- [Insecure Storage](mobile-iot/insecure-storage.md): problemi di storage non sicuro su mobile/IoT.
- [Certificate Pinning](mobile-iot/certificate-pinning.md): implementazione e bypass del pinning.
- [BLE Attacks](mobile-iot/ble-attacks.md): attacchi su Bluetooth Low Energy.
- [Containers](mobile-iot/containers.md): uso di container in ambienti IoT e rischi associati.

## Post-exploitation

- [Shells](post-exploitation/shells.md): gestione di shell remoti e tecniche di stabilizzazione.
- [C2](post-exploitation/c2.md): panoramica di server C2 e protocolli usati per agenti.
- [Persistence](post-exploitation/persistence.md): tecniche per persistence e loro rilevamento.
- [Lateral Movement](post-exploitation/lateral-movement.md): movimenti laterali in reti aziendali.
- [Steganography](post-exploitation/steganography.md): uso di steganografia per esfiltrazione e covert channels.

## Reporting

- [Reporting](reporting/reporting-guide.md): linee guida per redigere report di sicurezza chiari e ripetibili.
- [Hardening](reporting/hardening.md): misure di hardening e checklist di remediation.

## Tools

- [Tooling Overview](tools/tooling-overview.md): panoramica degli strumenti comunemente usati in red team/blue team.
- [Forensics](tools/forensics.md): strumenti e tecniche forensi per acquisizione e analisi delle prove.
- [Exploitation Frameworks](tools/exploitation-frameworks.md): elenco e confronto di framework di exploitation.
- [Fuzzing](tools/fuzzing.md): introduzione al fuzzing e strumenti principali.
- [Wireless Tools](tools/wireless-tools.md): strumenti per testing di reti wireless.
- [Cloud Tools](tools/cloud-tools.md): strumenti per assessment di sicurezza cloud.
- [Debugging Tools](tools/debugging-tools.md): strumenti utili per debug e analisi dinamica.

Aggiungi nuove guide seguendo il [TEMPLATE](../TEMPLATE.md).
