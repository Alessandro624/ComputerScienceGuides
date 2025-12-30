# Comandi Git Utili

## Scopo

Questa guida raccoglie i comandi Git più utili per la gestione del codice sorgente, il branching, la sincronizzazione con repository remoti e il ripristino di modifiche.

## Prerequisiti

- Git >= 2.0 installato
- Account su piattaforma Git (GitHub, GitLab, Bitbucket)
- Conoscenza base della linea di comando

## Installazione

### Windows

Scarica Git dal [sito ufficiale](https://git-scm.com/download/win) e segui le istruzioni di installazione.

### Linux (Debian/Ubuntu)

```bash
sudo apt-get update
sudo apt-get install git
```

### macOS

```bash
brew install git
```

### Configurazione iniziale

```bash
git config --global user.name "Tuo Nome"
git config --global user.email "tua@email.com"
git config --global init.defaultBranch main
```

---

## Sincronizzazione con il Repository Remoto

### Aggiornare la copia locale con le modifiche da remoto

```sh
git pull
```

## Aggiunta e Commit dei File

### Aggiungere un file all'area di stage

```sh
git add [path]
```

Opzioni:

- `-A` | `--all` → Aggiunge tutti i file della cartella locale

### Inviare le modifiche al repository locale

```sh
git commit
```

Opzioni:

- `-a` | `--all` → Effettua il commit di tutti i file modificati
- `-m "messaggio"` → Aggiunge un messaggio di commit

### Inserire le modifiche locali nel repository online

```sh
git push
```

## Controllo dello Stato e della Cronologia

### Mostrare lo stato della cartella di lavoro e dell'area di stage

```sh
git status
```

### Mostrare i commit e le loro informazioni

```sh
git log
```

Opzioni:

- `--oneline` → Mostra solo l'identificativo e il branch di ogni commit

## Gestione dei Branch

### Elencare, creare o eliminare rami

```sh
git branch
```

Opzioni:

- `-l` | `--list` → Elenca i rami
- `-d [name]` | `--delete [name]` → Elimina un ramo
- `-m [oldname] [newname]` | `--move [oldname] [newname]` → Rinomina un ramo
- `-c [oldname] [newname]` | `--copy [oldname] [newname]` → Copia un ramo

### Spostarsi in un altro ramo o commit specifico

```sh
git checkout name
```

- Le modifiche non inviate vengono trasportate nel nuovo ramo
- Il comando fallisce se ci sono conflitti nelle modifiche

Opzioni:

- `-b` → Crea e spostati direttamente sul nuovo ramo

### Alternativa a `checkout` per cambiare branch

```sh
git switch name
```

Opzioni:

- `-c` → Crea il ramo e spostati

### Effettuare un merge del ramo specificato in quello corrente

```sh
git merge name
```

- Potrebbero esserci conflitti evidenziati da Git

## Creazione e Clonazione di Repository

### Creare e inizializzare un nuovo repository locale

```sh
git init
```

Opzioni:

- `-b branch_name` | `--initial-branch=branch_name` → Modifica il nome del branch originale (default: `master`)

### Clonare un repository remoto

```sh
git clone remote_url
```

Opzioni:

- `-o name` | `--origin name` → Cambia il nome del repository remoto da `origin` a `name`
- `-b name` | `--branch name` → Clona il branch specificato invece di `origin`

## Gestione delle Modifiche Temporanee

### Nascondere le modifiche in una cartella di lavoro nascosta

```sh
git stash
```

Opzioni:

- `git stash add` → Aggiunge le modifiche all'area nascosta
- `git stash list` → Mostra le modifiche salvate
- `git stash show` → Mostra il contenuto dello stash
- `git stash pop` → Ripristina l'ultima modifica nascosta

## Ripristino e Differenze

### Ripristinare l'HEAD attuale nello stato specificato

```sh
git reset
```

### Controllare le modifiche disponibili nel repository remoto

```sh
git fetch
```

- Per applicare le modifiche serve un `git pull` dopo il `fetch`

### Mostrare le differenze tra commit o tra l'albero di lavoro

```sh
git diff
```

### Ripristinare i file dell'albero di lavoro

```sh
git restore
```

### Riportare un commit allo stato precedente

```sh
git revert
```

## Gestione dei Repository Remoti

### Visualizzare e gestire repository remoti

```sh
git remote
```

---

## Best Practices

- **Commit atomici**: Ogni commit dovrebbe rappresentare una singola modifica logica
- **Messaggi significativi**: Usa messaggi di commit chiari e descrittivi
- **Branch per feature**: Crea un branch separato per ogni nuova funzionalità
- **Pull prima di push**: Esegui sempre `git pull` prima di `git push`
- **Non modificare la storia pubblica**: Evita `git rebase` o `git commit --amend` su branch condivisi
- **Usa .gitignore**: Escludi file generati, dipendenze e file di configurazione locali
- **Convezione commit**: Considera l'uso di [Conventional Commits](https://www.conventionalcommits.org/)

## Riferimenti

- [Documentazione ufficiale Git](https://git-scm.com/doc)
- [Pro Git Book](https://git-scm.com/book/it/v2)
- [GitHub Docs](https://docs.github.com/)
- [Git Cheat Sheet](https://education.github.com/git-cheat-sheet-education.pdf)
