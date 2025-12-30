# Python Environments

## Scopo

Questa guida copre la gestione degli ambienti virtuali Python con venv, virtualenv, conda e Poetry per isolare dipendenze tra progetti.

## Prerequisiti

- Python 3.x installato
- pip package manager
- Terminale/Shell

---

## venv (Built-in)

### Creazione

```bash
# Crea ambiente
python -m venv myenv
python3 -m venv myenv

# Con Python specifico
python3.11 -m venv myenv
```

### Attivazione

```bash
# Linux/macOS
source myenv/bin/activate

# Windows (CMD)
myenv\Scripts\activate.bat

# Windows (PowerShell)
myenv\Scripts\Activate.ps1

# Verifica
which python
python --version
```

### Disattivazione

```bash
deactivate
```

### Utilizzo

```bash
# Installa pacchetti
pip install requests flask

# Lista pacchetti
pip list
pip freeze

# Esporta requirements
pip freeze > requirements.txt

# Installa da requirements
pip install -r requirements.txt
```

---

## virtualenv

### Installazione

```bash
pip install virtualenv
```

### Creazione

```bash
# Standard
virtualenv myenv

# Con Python specifico
virtualenv -p python3.11 myenv

# Senza pip
virtualenv --no-pip myenv
```

### Attivazione

```bash
# Stessa sintassi di venv
source myenv/bin/activate  # Linux/macOS
myenv\Scripts\activate     # Windows
```

---

## Conda

### Installazione

Scarica Miniconda o Anaconda da [conda.io](https://docs.conda.io/en/latest/miniconda.html).

### Gestione Ambienti

```bash
# Crea ambiente
conda create --name myenv python=3.11
conda create -n myenv python=3.11

# Lista ambienti
conda env list
conda info --envs

# Attiva
conda activate myenv

# Disattiva
conda deactivate

# Rimuovi
conda env remove --name myenv
```

### Pacchetti

```bash
# Installa
conda install numpy pandas
conda install -c conda-forge package

# Lista
conda list

# Esporta
conda env export > environment.yml

# Crea da file
conda env create -f environment.yml
```

### environment.yml

```yaml
name: myenv
channels:
  - conda-forge
  - defaults
dependencies:
  - python=3.11
  - numpy
  - pandas
  - pip
  - pip:
    - flask
    - requests
```

---

## Poetry

### Installazione

```bash
# Linux/macOS/WSL
curl -sSL https://install.python-poetry.org | python3 -

# Windows PowerShell
(Invoke-WebRequest -Uri https://install.python-poetry.org -UseBasicParsing).Content | python -
```

### Nuovo Progetto

```bash
# Crea progetto
poetry new myproject

# Inizializza in directory esistente
poetry init
```

### Struttura

```
myproject/
├── pyproject.toml
├── poetry.lock
├── myproject/
│   └── __init__.py
└── tests/
    └── __init__.py
```

### pyproject.toml

```toml
[tool.poetry]
name = "myproject"
version = "0.1.0"
description = "My project description"
authors = ["Name <email@example.com>"]

[tool.poetry.dependencies]
python = "^3.11"
requests = "^2.31.0"

[tool.poetry.group.dev.dependencies]
pytest = "^7.4.0"
black = "^23.0.0"

[build-system]
requires = ["poetry-core"]
build-backend = "poetry.core.masonry.api"
```

### Gestione Dipendenze

```bash
# Aggiungi dipendenza
poetry add requests
poetry add flask@^2.0

# Dipendenza dev
poetry add --group dev pytest

# Rimuovi
poetry remove requests

# Installa tutte
poetry install

# Aggiorna
poetry update
poetry update requests
```

### Esecuzione

```bash
# Attiva shell
poetry shell

# Esegui comando
poetry run python script.py
poetry run pytest
```

---

## pipenv

### Installazione

```bash
pip install pipenv
```

### Utilizzo

```bash
# Crea ambiente
pipenv --python 3.11

# Installa
pipenv install requests
pipenv install --dev pytest

# Attiva shell
pipenv shell

# Esegui
pipenv run python script.py

# Lock
pipenv lock

# Installa da Pipfile.lock
pipenv sync
```

---

## pyenv (Gestione Versioni Python)

### Installazione

```bash
# Linux/macOS
curl https://pyenv.run | bash

# Aggiungi a .bashrc/.zshrc
export PYENV_ROOT="$HOME/.pyenv"
export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init -)"
```

### Utilizzo

```bash
# Lista versioni disponibili
pyenv install --list

# Installa versione
pyenv install 3.11.5

# Lista versioni installate
pyenv versions

# Imposta globale
pyenv global 3.11.5

# Imposta locale (directory)
pyenv local 3.10.0

# Imposta per shell corrente
pyenv shell 3.9.0
```

---

## Confronto

| Tool | Uso Principale | Pro | Contro |
|------|----------------|-----|--------|
| venv | Semplice, built-in | Sempre disponibile | Solo ambienti |
| virtualenv | Cross-platform | Piu veloce di venv | Pacchetto extra |
| Conda | Data science | Gestisce Python + pacchetti | Pesante |
| Poetry | Progetti moderni | Dependency resolution | Curva apprendimento |
| pipenv | Alternativa a pip | Pipfile leggibile | Lento |

---

## Best Practices

- **Isolation**: Un ambiente per progetto
- **Requirements**: Sempre esporta dipendenze
- **Lock files**: Usa lock file per riproducibilita
- **.gitignore**: Ignora cartelle ambiente
- **Python version**: Specifica versione Python

### .gitignore

```gitignore
# Virtual environments
venv/
.venv/
env/
myenv/

# Poetry
poetry.lock

# Pipenv
Pipfile.lock
```

## Riferimenti

- [venv Documentation](https://docs.python.org/3/library/venv.html)
- [Poetry Documentation](https://python-poetry.org/docs/)
- [Conda Documentation](https://docs.conda.io/)
- [pyenv](https://github.com/pyenv/pyenv)
