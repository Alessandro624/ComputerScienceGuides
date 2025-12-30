# Makefile

## Scopo

Questa guida fornisce una panoramica su Make e Makefile, lo strumento classico per la build automation di progetti C/C++ e non solo.

## Prerequisiti

- GNU Make installato
- Compilatore (GCC, Clang)
- Editor di testo
- Conoscenza base della shell

## Installazione

### Linux (Debian/Ubuntu)

```bash
sudo apt-get install build-essential
```

### Windows

Installa tramite MinGW, MSYS2 o WSL.

### macOS

```bash
xcode-select --install
```

---

## Struttura Base

```makefile
# Commento

target: dependencies
 recipe  # TAB obbligatorio!
```

---

## Makefile Minimo

```makefile
# Compilatore
CC = gcc
CFLAGS = -Wall -Wextra

# Target principale
main: main.o utils.o
 $(CC) $(CFLAGS) -o main main.o utils.o

# Object files
main.o: main.c utils.h
 $(CC) $(CFLAGS) -c main.c

utils.o: utils.c utils.h
 $(CC) $(CFLAGS) -c utils.c

# Pulizia
clean:
 rm -f *.o main

.PHONY: clean
```

---

## Variabili

### Variabili Definite

```makefile
CC = gcc
CXX = g++
CFLAGS = -Wall -O2
LDFLAGS = -lm

# Uso
$(CC) $(CFLAGS) -o $@ $^
```

### Variabili Automatiche

| Variabile | Significato |
|-----------|-------------|
| `$@` | Nome del target |
| `$<` | Prima dipendenza |
| `$^` | Tutte le dipendenze |
| `$?` | Dipendenze piu recenti del target |
| `$*` | Stem del pattern |

### Esempio

```makefile
%.o: %.c
 $(CC) $(CFLAGS) -c $< -o $@
```

---

## Pattern Rules

```makefile
# Compila tutti i .c in .o
%.o: %.c
 $(CC) $(CFLAGS) -c $< -o $@

# Compila tutti i .cpp in .o
%.o: %.cpp
 $(CXX) $(CXXFLAGS) -c $< -o $@
```

---

## Funzioni

### Wildcard

```makefile
# Trova tutti i file .c
SRCS = $(wildcard src/*.c)

# Sostituisci estensione
OBJS = $(SRCS:.c=.o)
OBJS = $(patsubst %.c,%.o,$(SRCS))
```

### Altre Funzioni

```makefile
# Aggiungi prefisso/suffisso
$(addprefix build/,$(OBJS))
$(addsuffix .o,$(NAMES))

# Filtra
$(filter %.c,$(FILES))
$(filter-out %.h,$(FILES))

# Shell
DATE = $(shell date +%Y%m%d)
```

---

## Makefile Completo

```makefile
# Configurazione
CC = gcc
CXX = g++
CFLAGS = -Wall -Wextra -std=c11
CXXFLAGS = -Wall -Wextra -std=c++17
LDFLAGS =

# Directory
SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

# Files
SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRCS))
TARGET = $(BIN_DIR)/program

# Build mode
DEBUG ?= 0
ifeq ($(DEBUG), 1)
    CFLAGS += -g -O0 -DDEBUG
else
    CFLAGS += -O2 -DNDEBUG
endif

# Target principale
all: directories $(TARGET)

# Crea directory
directories:
 @mkdir -p $(OBJ_DIR) $(BIN_DIR)

# Linking
$(TARGET): $(OBJS)
 $(CC) $(OBJS) -o $@ $(LDFLAGS)

# Compilazione
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
 $(CC) $(CFLAGS) -c $< -o $@

# Pulizia
clean:
 rm -rf $(OBJ_DIR) $(BIN_DIR)

# Rebuild
rebuild: clean all

# Installazione
install: $(TARGET)
 install -m 755 $(TARGET) /usr/local/bin/

# Help
help:
 @echo "Targets disponibili:"
 @echo "  all      - Build del progetto"
 @echo "  clean    - Rimuove file generati"
 @echo "  rebuild  - Clean + build"
 @echo "  install  - Installa l'eseguibile"
 @echo ""
 @echo "Opzioni:"
 @echo "  DEBUG=1  - Build di debug"

.PHONY: all clean rebuild install help directories
```

---

## Dipendenze Automatiche

```makefile
DEPFLAGS = -MMD -MP
CFLAGS += $(DEPFLAGS)

# Include file .d generati
-include $(OBJS:.o=.d)
```

---

## Condizionali

```makefile
# Sistema operativo
ifeq ($(OS),Windows_NT)
    RM = del /Q
    EXE = .exe
else
    RM = rm -f
    EXE =
endif

# Variabile definita
ifdef DEBUG
    CFLAGS += -g
endif

# Variabile vuota
ifeq ($(strip $(VAR)),)
    # VAR e vuota
endif
```

---

## Multi-target

```makefile
.PHONY: all lib app test

all: lib app

lib:
 $(MAKE) -C lib/

app: lib
 $(MAKE) -C app/

test: lib
 $(MAKE) -C test/
 ./test/run_tests

clean:
 $(MAKE) -C lib/ clean
 $(MAKE) -C app/ clean
 $(MAKE) -C test/ clean
```

---

## Comandi Make

```bash
# Build default
make

# Target specifico
make clean
make install

# Variabili da linea di comando
make DEBUG=1
make CC=clang

# Parallelismo
make -j4
make -j$(nproc)

# Verbose
make VERBOSE=1

# Dry run
make -n

# Directory diversa
make -C subdir/
```

---

## Best Practices

- **TAB**: Usa sempre TAB per le recipe (non spazi)
- **PHONY**: Dichiara target non-file come .PHONY
- **Variabili**: Usa variabili per flessibilita
- **Dipendenze**: Genera automaticamente con -MMD
- **Modularita**: Dividi in file inclusi con `include`

## Riferimenti

- [GNU Make Manual](https://www.gnu.org/software/make/manual/)
- [Make Tutorial](https://makefiletutorial.com/)
