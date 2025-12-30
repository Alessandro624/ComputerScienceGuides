# Bash Scripting

## Scopo

Questa guida fornisce una panoramica su Bash scripting per l'automazione di task su sistemi Unix/Linux.

## Prerequisiti

- Sistema Unix/Linux o WSL
- Bash shell (versione 4+)
- Editor di testo
- Conoscenza base comandi Linux

---

## Script Base

### Struttura Minima

```bash
#!/bin/bash

# Commento
echo "Hello, World!"
```

### Esecuzione

```bash
# Rendi eseguibile
chmod +x script.sh

# Esegui
./script.sh
bash script.sh
```

---

## Variabili

### Definizione e Uso

```bash
# Assegnazione (no spazi!)
name="Mario"
count=10

# Uso
echo "Hello, $name"
echo "Count: ${count}"

# Read-only
readonly PI=3.14

# Variabili d'ambiente
export PATH="$PATH:/custom/path"
```

### Variabili Speciali

| Variabile | Significato |
|-----------|-------------|
| `$0` | Nome script |
| `$1-$9` | Argomenti posizionali |
| `$#` | Numero argomenti |
| `$@` | Tutti gli argomenti (array) |
| `$*` | Tutti gli argomenti (stringa) |
| `$?` | Exit status ultimo comando |
| `$$` | PID processo corrente |
| `$!` | PID ultimo processo background |

---

## Input/Output

### Echo e Printf

```bash
echo "Testo semplice"
echo -n "Senza newline"
echo -e "Con\tescape\n"

printf "Nome: %s, Eta: %d\n" "$name" "$age"
printf "%10s | %-10s\n" "Col1" "Col2"
```

### Read Input

```bash
read -p "Inserisci nome: " name
read -s -p "Password: " password  # Silenzioso
read -t 5 input  # Timeout 5 secondi
read -a array    # Leggi in array
```

### Redirection

```bash
# Output
command > file.txt      # Sovrascrivi
command >> file.txt     # Append
command 2> error.txt    # Solo stderr
command &> all.txt      # stdout + stderr
command > out.txt 2>&1  # Redirect stderr a stdout

# Input
command < input.txt
command << EOF
linea 1
linea 2
EOF
```

---

## Condizionali

### If-Else

```bash
if [ condition ]; then
    echo "True"
elif [ other_condition ]; then
    echo "Other"
else
    echo "False"
fi

# Forma compatta
[ condition ] && echo "True" || echo "False"
```

### Test Conditions

```bash
# Stringhe
[ "$str" = "value" ]    # Uguaglianza
[ "$str" != "value" ]   # Diverso
[ -z "$str" ]           # Vuota
[ -n "$str" ]           # Non vuota

# Numeri
[ "$a" -eq "$b" ]  # Uguale
[ "$a" -ne "$b" ]  # Diverso
[ "$a" -lt "$b" ]  # Minore
[ "$a" -le "$b" ]  # Minore o uguale
[ "$a" -gt "$b" ]  # Maggiore
[ "$a" -ge "$b" ]  # Maggiore o uguale

# File
[ -f "$file" ]  # File esiste
[ -d "$dir" ]   # Directory esiste
[ -r "$file" ]  # Leggibile
[ -w "$file" ]  # Scrivibile
[ -x "$file" ]  # Eseguibile
[ -s "$file" ]  # Non vuoto

# Logici
[ cond1 ] && [ cond2 ]  # AND
[ cond1 ] || [ cond2 ]  # OR
[ ! condition ]          # NOT
```

### Double Brackets (Bash)

```bash
# Supporta regex e glob
if [[ "$str" == pattern* ]]; then
    echo "Match"
fi

if [[ "$str" =~ ^[0-9]+$ ]]; then
    echo "E' un numero"
fi
```

### Case

```bash
case "$var" in
    start)
        echo "Starting..."
        ;;
    stop|kill)
        echo "Stopping..."
        ;;
    *)
        echo "Unknown: $var"
        ;;
esac
```

---

## Cicli

### For

```bash
# Lista
for item in apple banana orange; do
    echo "$item"
done

# Range
for i in {1..10}; do
    echo "$i"
done

# C-style
for ((i=0; i<10; i++)); do
    echo "$i"
done

# File
for file in *.txt; do
    echo "Processing: $file"
done
```

### While

```bash
count=0
while [ $count -lt 10 ]; do
    echo "$count"
    ((count++))
done

# Leggi file riga per riga
while IFS= read -r line; do
    echo "$line"
done < file.txt
```

### Until

```bash
until [ condition ]; do
    # Esegui finche condition e falsa
done
```

---

## Funzioni

```bash
# Definizione
function greet() {
    local name="$1"  # Variabile locale
    echo "Hello, $name!"
    return 0
}

# Alternativa
greet() {
    echo "Hello, $1!"
}

# Chiamata
greet "Mario"

# Return value
result=$(greet "Mario")
exit_code=$?
```

---

## Array

```bash
# Definizione
arr=(one two three)
declare -a arr

# Accesso
echo "${arr[0]}"      # Primo elemento
echo "${arr[@]}"      # Tutti gli elementi
echo "${#arr[@]}"     # Lunghezza

# Modifica
arr[3]="four"
arr+=("five")

# Iterazione
for item in "${arr[@]}"; do
    echo "$item"
done

# Slice
echo "${arr[@]:1:2}"  # Elementi 1-2
```

### Array Associativi

```bash
declare -A dict
dict[name]="Mario"
dict[age]=30

echo "${dict[name]}"
echo "${!dict[@]}"    # Keys
echo "${dict[@]}"     # Values
```

---

## Manipolazione Stringhe

```bash
str="Hello World"

# Lunghezza
echo "${#str}"

# Substring
echo "${str:0:5}"    # Hello
echo "${str:6}"      # World

# Sostituzione
echo "${str/World/Bash}"      # Prima occorrenza
echo "${str//l/L}"            # Tutte

# Rimozione
echo "${str#Hello }"   # Rimuovi prefisso
echo "${str%World}"    # Rimuovi suffisso

# Default
echo "${var:-default}"  # Se var vuota/unset
echo "${var:=default}"  # Assegna se vuota
```

---

## Aritmetica

```bash
# let
let result=5+3
let result++

# $(( ))
result=$((5 + 3))
result=$((a * b))

# expr (legacy)
result=$(expr 5 + 3)
```

---

## Error Handling

```bash
# Exit on error
set -e

# Exit on undefined variable
set -u

# Pipe fail
set -o pipefail

# Combinato
set -euo pipefail

# Trap
trap 'echo "Error on line $LINENO"' ERR
trap 'cleanup' EXIT

cleanup() {
    echo "Cleaning up..."
    rm -f /tmp/tempfile
}
```

---

## Script Template

```bash
#!/bin/bash
set -euo pipefail

# Variabili
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/tmp/script.log"

# Funzioni
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

error() {
    log "ERROR: $*" >&2
    exit 1
}

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS] ARGUMENT

Options:
    -h, --help      Show this help
    -v, --verbose   Verbose output
EOF
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            exit 0
            ;;
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        *)
            ARG="$1"
            shift
            ;;
    esac
done

# Main
main() {
    log "Starting script..."
    # Logica principale
    log "Done."
}

main "$@"
```

---

## Best Practices

- **Shebang**: Usa sempre `#!/bin/bash`
- **set -euo pipefail**: Abilita strict mode
- **Quoting**: Quota sempre le variabili `"$var"`
- **local**: Usa variabili locali nelle funzioni
- **Logging**: Implementa logging consistente

## Riferimenti

- [Bash Manual](https://www.gnu.org/software/bash/manual/)
- [ShellCheck](https://www.shellcheck.net/)
- [Bash Guide](https://mywiki.wooledge.org/BashGuide)
