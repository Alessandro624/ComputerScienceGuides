# Guida Linux e WSL

## Scopo

Questa guida raccoglie i comandi Linux più utili per lo sviluppo e l'amministrazione di sistema. Include istruzioni per il setup di WSL (Windows Subsystem for Linux), comandi di base e strumenti di sviluppo.

## Prerequisiti

- Windows 10/11 (per WSL) o distribuzione Linux
- Privilegi di amministratore per l'installazione
- Terminale/Shell

---

## Setup WSL (Windows Subsystem for Linux)

### Installazione WSL

```bash
wsl --install
wsl --update
wsl --shutdown
```

## Aggiornare i programmi

```bash
sudo apt update && sudo apt upgrade  # aggiorna tutti i programmi
```

## Installazione editor e applicazioni

```bash
sudo apt install gnome-text-editor -y  # avviare con gnome-text-editor ... (es. ~/.bashrc)
sudo apt install gimp -y  # avviare con gimp
sudo apt install nautilus -y  # avviare con nautilus
sudo apt install vlc -y  # avviare con vlc
sudo apt install x11-apps -y  # avviare con xcalc oppure xclock oppure xeyes
sudo apt install g++ gdb make ninja-build rsync zip
```

## Installazione Google Chrome

```bash
cd /tmp
wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
sudo apt install --fix-missing ./google-chrome-stable_current_amd64.deb  # avviare con google-chrome
```

## Installazione VS Code

```bash
sudo apt install snapd
sudo snap install code --classic  # avviare con code
```

## Installazione e disinstallazione MPI

```bash
sudo apt install libopenmpi-dev openmpi-bin
sudo apt-get remove openmpi-bin  # oppure aggiungere --auto-remove prima di openmpi-bin
```

---

## Comandi Linux Utili

### Comandi generali

```bash
man          # manuale
--help       # manuale specifico per un comando
exit         # uscire dal terminale
ls           # visualizza file e cartelle
  -s         # mostra size in blocchi
  -h         # leggibilità size migliorata (--si con potenze di 1000 e non 1024)
  -1         # lista verticale (colonna singola)
  -a         # vedi anche nascoste
  -R         # vedi ad albero con file interni a cartelle
  -l         # più informazioni su cartelle/file
  --sort=WORD # ordina rispetto WORD (di default lessicografico per nome)
  --time=WORD # modifica il tipo di tempo da mostrare
cd           # spostarsi tra cartelle
cp [file1] [file2] # copia file
cp [file1] [file2] … [cartella] # spostare più file in una cartella
mkdir        # creazione cartella
rm           # rimozione file
rm -r        # rimozione cartella con tutti i file all'interno
rmdir        # rimozione cartella con avviso se ci sono file nella cartella
mv [nome vecchio] [nome nuovo] # rinominare file
mv [file1] [file2] … [cartella] # spostare più file in una cartella
clear        # pulizia terminale
code         # apertura Visual Studio Code
htop -H      # visualizzazione processi/thread in tempo reale
pwd          # visualizza percorso corrente
less [nomefile] # mostra file
head [nomefile] # mostra prime 10 linee del file
tail [nomefile] # mostra ultime 10 linee del file
file [nomefile] # analizza file
sed [opzioni] [nomefile] # seleziona righe di un file e stampa
grep [paroladacercare] [nomefile] # mostra le linee del file in cui è presente la parola da cercare
wc [nomefile] # numero di linee, parole e caratteri nel file
sort [file]   # ordina dati
uniq [file]   # elimina righe duplicate
who          # mostra la lista degli utenti che hanno fatto log in
cat [file1] [file2] > [file0]  # concatena file1 e file2 a file0
chmod [who operation permission] # modifica i permessi di un file
ps           # mostra processi
sleep [tempoinsecondi] # metti in background un processo per alcuni secondi
bg           # metti in background
jobs         # lista di processi in esecuzione, background o sospesi
fg %[PID]    # fai ripartire il processo con PID
kill %[PID]  # termina processo con PID
df .         # spazio rimasto su disco
gzip [file]  # comprimi file
gunzip [file.gz]  # decomprimi file
zcat [file.gz] # leggi file .gz senza decomprimere
diff [file1] [file2] # mostra le differenze fra due file
find          # cerca in base a parametri tra cartelle e file
history       # mostra una lista ordinata dei comandi usati
perl -ne 'codice; codice;...' # esegue codice perl su shell
basename 'path cartella/file' # restituisce solo il nome del file
dirname 'path cartella/file' # restituisce il path per raggiungere la cartella/file
ifconfig      # configurazione corrente dell'interfaccia di rete
netstat       # informazioni relative alla rete
nslookup      # risoluzione dominio sito in indirizzo IP
telnet        # connessione a sito/mail server
```

### Comandi Speciali

```bash
TAB          # suggerimenti comandi, file, cartelle, ecc...
Frecce su e giù # scorrere comandi precedenti
CTRL+R       # cerca comandi precedenti contenenti una stringa
CTRL+C       # interruzione esecuzione
CTRL+L       # pulizia terminale
CTRL+D       # uscita dal terminale
CTRL+Z       # sospendi job in esecuzione
```

### Caratteri Speciali Linux

```bash
.            # cartella corrente
..           # cartella precedente
~            # cartella home principale
>            # manda l'output
2>           # manda gli errori
>&           # manda output ed errori
>>           # aggiungi output (append)
<            # manda l'input
|            # pipe (output di ciò che è a sinistra diventa input di ciò che è a destra)
*            # significa 0 o più caratteri
?            # significa un qualsiasi singolo carattere
[]           # significa tutti i file che contengono uno dei valori inseriti nelle []
! oppure ^   # negazione (non contengono)
```

### Variabili di Ambiente

```bash
env          # mostra tutte le variabili di ambiente
export       # modifica o crea variabili di ambiente
alcune più importanti:
  $SHELL
  $PATH
  $HOME
aggiungere una variabile d'ambiente permanente e non locale:
  nano ~/.bashrc
  export MY_VAR="HelloWorld"
  source ~/.bashrc
```

---

## C++ Compilazione ed Esecuzione

### Compilazione e Esecuzione

```bash
g++ -std=c++11 -o nome nome.cpp  # compilazione
./nome  # esecuzione
```

### Passaggio Input da File

```bash
type input.txt ./programma
```

### Ottimizzazione Compilazione

```bash
-O0  # default
-O1  # oppure -O
-O2  # ottimizzazione intermedia
-O3  # consigliato per algoritmi paralleli e sistemi distribuiti
-Os   # ottimizzazione per ridurre la dimensione
-Ofast # ottimizzazione per massima velocità
```

### Codice Misto C/C++ e Assembly

```bash
g++ -g nome.cpp
objdump -S filebinario
```

#### AArch64 (ARM)

```bash
aarch64-linux-gnu-gcc -g nome.cpp
aarch64-linux-gnu-objdump -S a.out
```

---

## Programma MPI

### Compilazione ed Esecuzione Programma MPI

```bash
mpiCC nome.cpp
mpirun -np 4 ./a.out  # scegliere numero processori opportunamente
```

## Posix Thread

### Compilazione ed Esecuzione Posix Thread

```bash
g++ nome.c/cpp -o nome -lpthread
./nome
time ./nome  # per ottenere i tempi di esecuzione
```

---

### Modifica Carattere di Tabulazione

```bash
expand -t 4 programma.py  # mostra a schermo
expand -t 4 programma.py > new_programma.py  # crea e salva in nuovo programma
```

---

## Visualizzare in Formato ASCII un File

```bash
hexdump -C programma.py | less
```

---

## Comandi AArch64

```bash
aarch64-linux-gnu-gcc -c [nome.s]  # compila e crea file .o
aarch64-linux-gnu-gcc -o [nome] -static [nome.s]  # assembla e linka
qemu-aarch64 [nome oppure nome.o]  # esegui
aarch64-linux-gnu-objdump -D [nome.o]  # disassembla
aarch64-linux-gnu-objdump -j.[nomesezione] -s [nome.o]  # estrazione contenuto delle sezioni
```

---

## Compilare ed Eseguire Java

```bash
javac nome.java
java nome
```

---

## Disattivare Hyper-V

```bash
bcdedit /set hypervisorlaunchtype off
```

---

## Best Practices

- **Backup regolari**: Usa rsync o tar per backup incrementali
- **Permessi minimi**: Applica il principio del privilegio minimo (chmod)
- **Alias utili**: Crea alias in ~/.bashrc per comandi frequenti
- **Script riutilizzabili**: Automatizza task ripetitivi con script bash
- **Aggiornamenti**: Mantieni il sistema aggiornato regolarmente
- **Log management**: Monitora i log con journalctl e tail -f

## Riferimenti

- [Linux Command Library](https://linuxcommandlibrary.com/)
- [WSL Documentation](https://docs.microsoft.com/en-us/windows/wsl/)
- [Ubuntu Documentation](https://help.ubuntu.com/)
- [Bash Reference Manual](https://www.gnu.org/software/bash/manual/)
