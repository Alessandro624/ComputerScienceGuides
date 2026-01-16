# Fuzzing Tools

## Scopo

Questa guida copre tecniche e tool di fuzzing per scoprire vulnerabilità in applicazioni, protocolli e file format attraverso input automatizzati.

## Prerequisiti

- Conoscenza programmazione base
- Ambiente di test isolato
- Target application source/binary
- **Autorizzazione per testing**

---

## Concetti Base

| Termine | Descrizione |
|---------|-------------|
| Fuzzer | Tool che genera input |
| Corpus | Set di input iniziali |
| Mutation | Modifica di input esistenti |
| Generation | Creazione input da grammar |
| Coverage | Codice eseguito durante fuzzing |
| Crash | Input che causa errore |

---

## Code Quality & Assurance Tools

| Tool | Linguaggio | Uso |
|------|------------|-----|
| SpotBugs | Java | Static analysis |
| FindSecBugs | Java | Security-focused analysis |
| SonarQube | Multi | Code quality platform |
| Radamsa | Multi | General-purpose fuzzer |
| Peach | Multi | Protocol fuzzing |
| Mutiny | Network | Network protocol fuzzer |
| AFL | C/C++ | Coverage-guided fuzzing |

---

## Web Fuzzing

### Ffuf

```bash
# Installazione
apt install ffuf

# Directory bruteforce
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://target/FUZZ

# File extension
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://target/FUZZ -e .php,.html,.txt

# Virtual hosts
ffuf -w subdomains.txt -H "Host: FUZZ.target.com" -u http://target

# GET parameter
ffuf -w params.txt -u "http://target/page?FUZZ=value"

# POST data
ffuf -w wordlist.txt -X POST -d "username=FUZZ&password=test" -u http://target/login

# Filtering
ffuf -w wordlist.txt -u http://target/FUZZ -fc 404 -fs 0 -fw 100

# Speed control
ffuf -w wordlist.txt -u http://target/FUZZ -rate 100 -t 50

# Output
ffuf -w wordlist.txt -u http://target/FUZZ -o results.json -of json
```

### Wfuzz

```bash
# Installazione
apt install wfuzz

# Directory
wfuzz -w wordlist.txt http://target/FUZZ

# Parameters
wfuzz -w wordlist.txt http://target/page?FUZZ=value

# POST
wfuzz -w wordlist.txt -d "user=FUZZ" http://target/login

# Headers
wfuzz -w wordlist.txt -H "Cookie: session=FUZZ" http://target/

# Filter
wfuzz -w wordlist.txt --hc 404 --hl 10 http://target/FUZZ

# Multiple positions
wfuzz -w users.txt -w passwords.txt -d "user=FUZZ&pass=FUZ2Z" http://target/login
```

### Gobuster

```bash
# Directory mode
gobuster dir -u http://target -w wordlist.txt

# DNS mode
gobuster dns -d target.com -w subdomains.txt

# Virtual hosts
gobuster vhost -u http://target -w vhosts.txt

# Extensions
gobuster dir -u http://target -w wordlist.txt -x php,txt,html

# Threads
gobuster dir -u http://target -w wordlist.txt -t 50
```

### Feroxbuster

```bash
# Recursive scanning
feroxbuster -u http://target -w wordlist.txt

# Depth control
feroxbuster -u http://target -w wordlist.txt -d 3

# Extensions
feroxbuster -u http://target -w wordlist.txt -x php,html

# Output
feroxbuster -u http://target -w wordlist.txt -o results.txt
```

---

## Binary Fuzzing

### AFL++ (American Fuzzy Lop)

```bash
# Installazione
apt install afl++

# Compile con instrumentazione
afl-gcc -o target target.c
afl-g++ -o target target.cpp

# Per binari esistenti
afl-qemu-trace ./binary

# Crea corpus iniziale
mkdir input output
echo "test" > input/seed1

# Avvia fuzzing
afl-fuzz -i input -o output -- ./target @@

# Multiple cores
afl-fuzz -M main -i input -o output -- ./target @@
afl-fuzz -S secondary1 -i input -o output -- ./target @@
afl-fuzz -S secondary2 -i input -o output -- ./target @@

# Monitora
afl-whatsup output/
```

### LibFuzzer

```cpp
// Harness
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Chiama funzione target
    parse_data(data, size);
    return 0;
}
```

```bash
# Compile
clang++ -g -fsanitize=fuzzer,address target.cpp -o fuzzer

# Run
./fuzzer corpus/

# Options
./fuzzer -max_len=1000 -timeout=5 corpus/
```

### Honggfuzz

```bash
# Compile
honggfuzz-clang -o target target.c

# Run
honggfuzz -i input/ -o output/ -- ./target ___FILE___

# Persistent mode
honggfuzz -P -i input/ -- ./target
```

---

## Network Fuzzing

### Boofuzz

```python
from boofuzz import *

def main():
    session = Session(
        target=Target(
            connection=SocketConnection("TARGET", 8080, proto='tcp')
        )
    )

    s_initialize("request")
    s_string("GET", fuzzable=False)
    s_delim(" ", fuzzable=False)
    s_string("/", name="path")
    s_delim(" ", fuzzable=False)
    s_string("HTTP/1.1", fuzzable=False)
    s_static("\r\n\r\n")

    session.connect(s_get("request"))
    session.fuzz()

if __name__ == "__main__":
    main()
```

### Spike

```bash
# Crea template .spk
s_readline();
s_string("GET ");
s_string_variable("/");
s_string(" HTTP/1.1\r\n");
s_string("\r\n");

# Run
generic_send_tcp TARGET 80 template.spk 0 0
```

---

## API Fuzzing

### RESTler

```bash
# Compile spec
python restler.py compile --api_spec openapi.yaml

# Test
python restler.py test --grammar_file grammar.py

# Fuzz
python restler.py fuzz --grammar_file grammar.py
```

### Nuclei Fuzzing

```yaml
id: param-fuzz

info:
  name: Parameter Fuzzing
  severity: info

requests:
  - method: GET
    path:
      - "{{BaseURL}}?{{params}}"
    payloads:
      params: params.txt
    matchers:
      - type: word
        words:
          - "error"
```

---

## Format-Specific Fuzzing

### PDF (Peach Fuzzer)

```xml
<?xml version="1.0" encoding="utf-8"?>
<Peach>
    <DataModel name="PDFModel">
        <String value="%PDF-" token="true"/>
        <String name="version" value="1.4"/>
        <Blob name="content"/>
    </DataModel>
    
    <StateModel name="State">
        <State name="initial">
            <Action type="output">
                <DataModel ref="PDFModel"/>
            </Action>
        </State>
    </StateModel>
</Peach>
```

### Image (ImageMagick)

```bash
# Radamsa mutation
radamsa sample.jpg > fuzz.jpg
identify fuzz.jpg

# Loop
for i in {1..1000}; do
    radamsa sample.jpg > /tmp/fuzz.jpg
    timeout 5 convert /tmp/fuzz.jpg /tmp/out.png 2>&1
done
```

---

## Mutation Tools

### Radamsa

```bash
# Installazione
apt install radamsa

# Mutazione base
echo "test" | radamsa

# File mutation
radamsa sample.txt > mutated.txt

# Multiple outputs
radamsa -n 100 -o fuzz_%n.txt sample.txt
```

### Zzuf

```bash
# Mutazione con ratio
zzuf -r 0.01 < input.txt | ./target

# Con seed
zzuf -s 12345 -r 0.01 < input.txt
```

---

## Coverage Analysis

### Gcov

```bash
# Compile con coverage
gcc -fprofile-arcs -ftest-coverage -o target target.c

# Run
./target

# Generate report
gcov target.c
lcov --capture --directory . --output-file coverage.info
genhtml coverage.info --output-directory coverage_html
```

### LLVM Coverage

```bash
# Compile
clang -fprofile-instr-generate -fcoverage-mapping -o target target.c

# Run
LLVM_PROFILE_FILE="target.profraw" ./target

# Report
llvm-profdata merge target.profraw -o target.profdata
llvm-cov show ./target -instr-profile=target.profdata
```

---

## Crash Analysis

### Triaging

```bash
# Unique crashes
afl-cmin -i crashes/ -o unique/ -- ./target @@

# GDB analysis
gdb ./target
run < crash_input
bt full
```

### ASAN (Address Sanitizer)

```bash
# Compile
gcc -fsanitize=address -g -o target target.c

# Run
./target crash_input
# Detailed stack trace
```

---

## Wordlists

| List | Uso |
|------|-----|
| SecLists | Comprehensive collection |
| FuzzDB | Attack patterns |
| Assetnote | Discovery lists |
| dirbuster | Directory/file names |

```bash
# SecLists
git clone https://github.com/danielmiessler/SecLists.git

# Common paths
/usr/share/wordlists/dirb/common.txt
/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

---

## Best Practices

- **Isolation**: Ambiente isolato
- **Resources**: CPU/RAM adeguati
- **Corpus**: Input di qualità
- **Coverage**: Monitora coverage
- **Triage**: Analizza crash

## Riferimenti

- [AFL++](https://aflplus.plus/)
- [LibFuzzer](https://llvm.org/docs/LibFuzzer.html)
- [Ffuf](https://github.com/ffuf/ffuf)
- [Boofuzz](https://github.com/jtpereyda/boofuzz)
