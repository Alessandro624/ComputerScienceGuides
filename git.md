# Comandi Git Utili

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
