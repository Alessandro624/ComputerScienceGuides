# Guida a Valgrind

## Scopo

Questa guida spiega come utilizzare Valgrind per il debugging e il profiling di programmi C/C++. Copre l'individuazione di memory leak, problemi di gestione della memoria e l'analisi delle prestazioni.

## Prerequisiti

- Programma compilato con simboli di debug (`-g`)
- Linux (Valgrind non supporta nativamente Windows/macOS)
- Conoscenza base di C/C++ e gestione della memoria

---

Valgrind è un framework per il debugging e il profiling di programmi, particolarmente utile per individuare perdite di memoria e problemi di gestione della memoria in programmi scritti in C e C++.

## Installazione

### Su Linux (Debian/Ubuntu)

```bash
sudo apt-get install valgrind
```

## Utilizzo di Base

### Eseguire un programma con Valgrind

Per analizzare la gestione della memoria di un programma:

```bash
valgrind ./mio_programma
```

### Modalità Memcheck (per il controllo della memoria)

```bash
valgrind --leak-check=full --show-leak-kinds=all ./mio_programma
```

Questo comando verifica perdite di memoria e mostra dettagli su ogni perdita rilevata.

### Modalità Callgrind (per il profiling delle prestazioni)

```bash
valgrind --tool=callgrind ./mio_programma
```

Genera un report dettagliato sulle funzioni più eseguite.

### Modalità Massif (per l'analisi dell'uso della memoria)

```bash
valgrind --tool=massif ./mio_programma
```

Genera un report sull'allocazione della memoria durante l'esecuzione del programma.

## Visualizzazione dei Dati con Strumenti Grafici

### Massif-Visualizer

`massif-visualizer` è uno strumento grafico che permette di analizzare i dati generati da Massif in modo interattivo, visualizzando l'andamento dell'allocazione di memoria nel tempo.

#### Installazione Massif-Visualizer Su Linux (Debian/Ubuntu)

```bash
sudo apt-get install massif-visualizer
```

#### Utilizzo

Per utilizzarlo, genera il report con:

```bash
valgrind --tool=massif --massif-out-file=massif.out ./mio_programma
```

E aprilo con:

```bash
massif-visualizer ./massif.out
```

Massif-Visualizer mostrerà un grafico interattivo che permette di esaminare l'uso della memoria nel tempo e individuare i punti critici in cui il programma consuma più memoria.

### KCachegrind

`kcachegrind` è un visualizzatore grafico per i dati generati da Callgrind, utile per analizzare il comportamento del programma e individuare colli di bottiglia nel codice.

#### Installazione KCachegrind Su Linux (Debian/Ubuntu)

```bash
sudo apt-get install kcachegrind
```

#### Utilizzo KCachegrind

Per generare i dati con Callgrind:

```bash
valgrind --tool=callgrind --callgrind-out-file=callgrind.out ./mio_programma
```

E aprirli con:

```bash
kcachegrind ./callgrind.out
```

KCachegrind fornisce una rappresentazione visiva delle chiamate di funzione, evidenziando quali funzioni consumano più tempo di CPU. Inoltre, permette di navigare attraverso la gerarchia delle chiamate per individuare eventuali inefficienze nel codice.

## Risoluzione di Problemi Comuni

1. **Invalid read/write**: Controlla che gli accessi alla memoria avvengano solo su dati allocati correttamente.
2. **Use of uninitialized memory**: Assicurati che tutte le variabili siano inizializzate prima dell'uso.
3. **Memory leaks**: Se l'output di Valgrind segnala perdite di memoria, verifica che ogni `malloc()` o `new` abbia un corrispondente `free()` o `delete`.
4. **Eccessivo utilizzo di memoria**: Utilizza Massif e Massif-Visualizer per individuare i punti in cui il programma consuma più memoria del necessario.
5. **Ottimizzazione del codice**: Se Callgrind indica che alcune funzioni sono particolarmente costose, valuta la possibilità di ottimizzarle per ridurre il tempo di esecuzione.

---

## Best Practices

- **Compila con -g**: Includi sempre i simboli di debug per output più dettagliati
- **Disabilita ottimizzazioni**: Usa `-O0` durante il debugging per risultati accurati
- **Analizza regolarmente**: Integra Valgrind nel processo di CI/CD
- **Risolvi prima i memory leak**: Affronta prima le perdite di memoria, poi gli errori
- **Usa suppression file**: Crea file di soppressione per falsi positivi noti
- **Testa con input realistici**: Usa dataset rappresentativi per il profiling

## Riferimenti

- [Valgrind Documentation](https://valgrind.org/docs/manual/manual.html)
- [Memcheck Manual](https://valgrind.org/docs/manual/mc-manual.html)
- [Callgrind Manual](https://valgrind.org/docs/manual/cl-manual.html)
- [KCachegrind](https://kcachegrind.github.io/)
