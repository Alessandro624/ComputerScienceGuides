# Introduzione a Doxygen

Doxygen è uno strumento open-source che permette di creare documentazione direttamente dal codice sorgente, facilitando la comprensione e la manutenzione del software.

## Installazione

### Su Linux

Per installare Doxygen su sistemi basati su Debian/Ubuntu:

```bash
sudo apt-get install doxygen
```

Per sistemi basati su Red Hat/Fedora:

```bash
sudo dnf install doxygen
```

### Su Windows

Scarica l'installer dal [sito ufficiale di Doxygen](https://www.doxygen.nl/download.html) e segui le istruzioni per l'installazione.

### Su macOS

Utilizza Homebrew per installare Doxygen:

```bash
brew install doxygen
```

## Configurazione del Progetto

Nella directory principale del tuo progetto, esegui:

```bash
doxygen -g
```

Questo comando genera un file `Doxyfile` con le impostazioni predefinite.

## Personalizzazione del Doxyfile

Apri il file `Doxyfile` con un editor di testo e modifica le seguenti opzioni:

- **PROJECT_NAME**: Nome del progetto.
- **OUTPUT_DIRECTORY**: Directory in cui verrà salvata la documentazione generata.
- **INPUT**: Directory o file da cui Doxygen estrarrà la documentazione.
- **RECURSIVE**: Imposta su `YES` se desideri che Doxygen analizzi le sottodirectory.

## Aggiunta di Commenti nel Codice

Doxygen utilizza commenti speciali per generare la documentazione. Ecco un esempio in C++:

```cpp
/**
 * @brief Calcola la somma di due interi.
 * @param a Primo intero.
 * @param b Secondo intero.
 * @return La somma di a e b.
 */
int somma(int a, int b) {
    return a + b;
}
```

I principali comandi Doxygen includono:

- **@brief**: Descrizione breve della funzione o classe.
- **@param**: Descrizione dei parametri della funzione.
- **@return**: Descrizione del valore restituito dalla funzione.

## Generazione della Documentazione

Dopo aver configurato il `Doxyfile` e aggiunto i commenti nel codice, genera la documentazione eseguendo:

```bash
doxygen Doxyfile
```

La documentazione verrà creata nella directory specificata in formato HTML e/o LaTeX, a seconda delle impostazioni del `Doxyfile`.

## Visualizzazione della Documentazione

Apri il file `index.html` presente nella directory di output specificata per visualizzare la documentazione nel browser.
