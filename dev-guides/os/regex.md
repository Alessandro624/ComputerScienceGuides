# Regex (Espressioni Regolari)

## Scopo

Questa guida fornisce un riferimento completo per le espressioni regolari, pattern matching e text processing.

## Prerequisiti

- Terminale o editor con supporto regex
- Comprensione base stringhe

---

## Metacaratteri

| Carattere | Significato |
|-----------|-------------|
| `.` | Qualsiasi carattere (eccetto newline) |
| `^` | Inizio stringa/linea |
| `$` | Fine stringa/linea |
| `*` | 0 o piu occorrenze |
| `+` | 1 o piu occorrenze |
| `?` | 0 o 1 occorrenza |
| `\|` | Alternativa (OR) |
| `()` | Gruppo |
| `[]` | Classe di caratteri |
| `{}` | Quantificatore |
| `\` | Escape |

---

## Classi di Caratteri

### Predefinite

| Pattern | Equivalente | Significato |
|---------|-------------|-------------|
| `\d` | `[0-9]` | Cifra |
| `\D` | `[^0-9]` | Non cifra |
| `\w` | `[a-zA-Z0-9_]` | Word character |
| `\W` | `[^a-zA-Z0-9_]` | Non word |
| `\s` | `[ \t\n\r\f]` | Whitespace |
| `\S` | `[^ \t\n\r\f]` | Non whitespace |

### Personalizzate

```regex
[abc]       # a, b, o c
[a-z]       # Lettera minuscola
[A-Z]       # Lettera maiuscola
[a-zA-Z]    # Qualsiasi lettera
[0-9]       # Cifra
[^abc]      # NON a, b, c
[a-z0-9]    # Lettera minuscola o cifra
```

---

## Quantificatori

| Pattern | Significato |
|---------|-------------|
| `*` | 0 o piu (greedy) |
| `+` | 1 o piu (greedy) |
| `?` | 0 o 1 (greedy) |
| `{n}` | Esattamente n |
| `{n,}` | Almeno n |
| `{n,m}` | Da n a m |
| `*?` | 0 o piu (lazy) |
| `+?` | 1 o piu (lazy) |
| `??` | 0 o 1 (lazy) |

### Greedy vs Lazy

```regex
# Stringa: <div>content</div>

<.*>    # Greedy: <div>content</div>
<.*?>   # Lazy: <div>
```

---

## Ancore

| Pattern | Significato |
|---------|-------------|
| `^` | Inizio stringa |
| `$` | Fine stringa |
| `\b` | Word boundary |
| `\B` | Non word boundary |
| `\A` | Inizio assoluto |
| `\Z` | Fine assoluto |

```regex
^hello      # "hello" a inizio
world$      # "world" a fine
\bword\b    # "word" come parola intera
```

---

## Gruppi

### Gruppi di Cattura

```regex
(abc)           # Gruppo cattura
(\d{3})-(\d{4}) # Due gruppi: 123-4567

# Riferimento
\1              # Primo gruppo
\2              # Secondo gruppo
```

### Gruppi Non-Cattura

```regex
(?:abc)         # Gruppo senza cattura
```

### Gruppi con Nome

```regex
(?<name>\w+)    # Gruppo nominato
(?P<name>\w+)   # Python syntax

# Riferimento
\k<name>        # Riferimento nominato
```

---

## Lookahead e Lookbehind

### Lookahead

```regex
# Positive lookahead: seguito da
\d+(?=€)        # Cifre seguite da €
foo(?=bar)      # "foo" seguito da "bar"

# Negative lookahead: NON seguito da
\d+(?!€)        # Cifre NON seguite da €
foo(?!bar)      # "foo" NON seguito da "bar"
```

### Lookbehind

```regex
# Positive lookbehind: preceduto da
(?<=€)\d+       # Cifre precedute da €
(?<=foo)bar     # "bar" preceduto da "foo"

# Negative lookbehind: NON preceduto da
(?<!€)\d+       # Cifre NON precedute da €
(?<!foo)bar     # "bar" NON preceduto da "foo"
```

---

## Flag/Modificatori

| Flag | Significato |
|------|-------------|
| `i` | Case insensitive |
| `g` | Global (tutte le occorrenze) |
| `m` | Multiline (^ e $ per ogni riga) |
| `s` | Dotall (. include newline) |
| `x` | Extended (ignora spazi, commenti) |
| `u` | Unicode |

```regex
/pattern/flags

/hello/i        # Case insensitive
/hello/gi       # Global + case insensitive
```

---

## Pattern Comuni

### Email

```regex
# Base
[\w.-]+@[\w.-]+\.\w+

# Completo
^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$
```

### URL

```regex
https?://[\w.-]+(?:/[\w./-]*)?

# Completo
https?://(?:www\.)?[-a-zA-Z0-9@:%._+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_+.~#?&/=]*)
```

### Telefono

```regex
# Italiano
(?:\+39)?\s*\d{3}[\s.-]?\d{3}[\s.-]?\d{4}

# Internazionale
\+?[\d\s.-]{10,}
```

### Codice Fiscale (Italia)

```regex
^[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]$
```

### Data

```regex
# DD/MM/YYYY
\d{2}/\d{2}/\d{4}

# YYYY-MM-DD (ISO)
\d{4}-\d{2}-\d{2}

# Validazione
^(0[1-9]|[12]\d|3[01])/(0[1-9]|1[0-2])/\d{4}$
```

### Ora

```regex
# HH:MM
^([01]\d|2[0-3]):[0-5]\d$

# HH:MM:SS
^([01]\d|2[0-3]):[0-5]\d:[0-5]\d$
```

### IP Address

```regex
# IPv4
\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b

# Validato
^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$
```

### Password

```regex
# Min 8 char, 1 upper, 1 lower, 1 digit
^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$

# Con carattere speciale
^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$
```

### HTML Tag

```regex
<(\w+)[^>]*>.*?</\1>    # Tag con contenuto
<(\w+)[^>]*/>           # Self-closing
<[^>]+>                 # Qualsiasi tag
```

### Spazi

```regex
^\s+|\s+$       # Trim
\s+             # Multipli spazi
```

---

## Esempi Linguaggi

### Python

```python
import re

# Match
if re.match(r'^\d+$', text):
    print("Solo numeri")

# Search
result = re.search(r'\d+', text)
if result:
    print(result.group())

# Find all
numbers = re.findall(r'\d+', text)

# Replace
cleaned = re.sub(r'\s+', ' ', text)

# Split
parts = re.split(r'[,;]\s*', text)

# Compile
pattern = re.compile(r'\b\w+\b')
words = pattern.findall(text)
```

### JavaScript

```javascript
// Match
if (/^\d+$/.test(text)) {
    console.log("Solo numeri");
}

// Search
const result = text.match(/\d+/);
if (result) {
    console.log(result[0]);
}

// Find all
const numbers = text.match(/\d+/g);

// Replace
const cleaned = text.replace(/\s+/g, ' ');

// Split
const parts = text.split(/[,;]\s*/);
```

### Bash/Grep

```bash
# Grep
grep -E '\d{3}-\d{4}' file.txt
grep -oE '[a-z]+@[a-z]+\.[a-z]+' file.txt

# Sed
sed -E 's/\s+/ /g' file.txt
sed -E 's/^(.*)$/prefix_\1/' file.txt

# Awk
awk '/pattern/ {print $0}' file.txt
```

---

## Tool Online

- [regex101.com](https://regex101.com/) - Test interattivo
- [regexr.com](https://regexr.com/) - Visualizzatore
- [debuggex.com](https://www.debuggex.com/) - Diagrammi

---

## Best Practices

- **Semplicita**: Pattern semplici quando possibile
- **Test**: Testa con casi limite
- **Commenti**: Usa flag `x` per pattern complessi
- **Escape**: Esegui escape caratteri speciali
- **Performance**: Evita backtracking eccessivo

## Riferimenti

- [Regular-Expressions.info](https://www.regular-expressions.info/)
- [MDN RegExp](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular_Expressions)
- [Python re](https://docs.python.org/3/library/re.html)
