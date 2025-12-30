# VSCode

## Scopo

Questa guida fornisce una panoramica di Visual Studio Code, configurazione, estensioni essenziali e produttivita.

## Prerequisiti

- VSCode installato
- Sistema operativo supportato

---

## Installazione

```bash
# Windows (winget)
winget install Microsoft.VisualStudioCode

# macOS (Homebrew)
brew install --cask visual-studio-code

# Linux (snap)
sudo snap install code --classic

# Linux (apt)
sudo apt install code
```

---

## Shortcuts Essenziali

### Generali

| Shortcut | Azione |
|----------|--------|
| `Ctrl+Shift+P` | Command Palette |
| `Ctrl+P` | Quick Open file |
| `Ctrl+,` | Settings |
| `Ctrl+` ` | Terminal integrato |
| `Ctrl+B` | Toggle Sidebar |
| `Ctrl+Shift+E` | Explorer |
| `Ctrl+Shift+F` | Search |
| `Ctrl+Shift+G` | Git |
| `Ctrl+Shift+X` | Extensions |

### Editing

| Shortcut | Azione |
|----------|--------|
| `Ctrl+D` | Seleziona prossima occorrenza |
| `Ctrl+Shift+L` | Seleziona tutte le occorrenze |
| `Alt+Click` | Multi-cursor |
| `Ctrl+Alt+Up/Down` | Aggiungi cursor sopra/sotto |
| `Ctrl+Shift+K` | Elimina riga |
| `Alt+Up/Down` | Sposta riga |
| `Shift+Alt+Up/Down` | Copia riga |
| `Ctrl+/` | Toggle commento |
| `Ctrl+Shift+A` | Block comment |
| `Ctrl+]` / `Ctrl+[` | Indent/Outdent |

### Navigazione

| Shortcut | Azione |
|----------|--------|
| `Ctrl+G` | Vai a riga |
| `Ctrl+Shift+O` | Vai a simbolo |
| `F12` | Vai a definizione |
| `Alt+F12` | Peek definition |
| `Shift+F12` | Trova riferimenti |
| `Ctrl+Tab` | Switch file |
| `Ctrl+\` | Split editor |
| `Ctrl+1/2/3` | Focus editor group |

### Debug

| Shortcut | Azione |
|----------|--------|
| `F5` | Start/Continue |
| `F9` | Toggle breakpoint |
| `F10` | Step over |
| `F11` | Step into |
| `Shift+F11` | Step out |
| `Shift+F5` | Stop |

---

## Settings

### settings.json

```json
{
  // Editor
  "editor.fontSize": 14,
  "editor.fontFamily": "'JetBrains Mono', 'Fira Code', Consolas",
  "editor.fontLigatures": true,
  "editor.tabSize": 2,
  "editor.insertSpaces": true,
  "editor.wordWrap": "on",
  "editor.minimap.enabled": false,
  "editor.cursorBlinking": "smooth",
  "editor.cursorSmoothCaretAnimation": "on",
  "editor.smoothScrolling": true,
  "editor.bracketPairColorization.enabled": true,
  "editor.guides.bracketPairs": true,
  "editor.formatOnSave": true,
  "editor.formatOnPaste": true,
  "editor.linkedEditing": true,
  "editor.suggest.preview": true,
  "editor.inlineSuggest.enabled": true,
  
  // Files
  "files.autoSave": "afterDelay",
  "files.autoSaveDelay": 1000,
  "files.trimTrailingWhitespace": true,
  "files.insertFinalNewline": true,
  "files.exclude": {
    "**/.git": true,
    "**/.DS_Store": true,
    "**/node_modules": true
  },
  
  // Workbench
  "workbench.colorTheme": "One Dark Pro",
  "workbench.iconTheme": "material-icon-theme",
  "workbench.startupEditor": "none",
  "workbench.editor.enablePreview": false,
  
  // Terminal
  "terminal.integrated.fontSize": 13,
  "terminal.integrated.defaultProfile.windows": "PowerShell",
  "terminal.integrated.defaultProfile.linux": "bash",
  
  // Git
  "git.autofetch": true,
  "git.confirmSync": false,
  "git.enableSmartCommit": true,
  
  // Language specific
  "[python]": {
    "editor.tabSize": 4
  },
  "[javascript]": {
    "editor.defaultFormatter": "esbenp.prettier-vscode"
  },
  "[typescript]": {
    "editor.defaultFormatter": "esbenp.prettier-vscode"
  },
  "[json]": {
    "editor.defaultFormatter": "esbenp.prettier-vscode"
  }
}
```

---

## Estensioni Essenziali

### Generali

| Estensione | Descrizione |
|------------|-------------|
| `GitHub Copilot` | AI assistant |
| `GitLens` | Git supercharged |
| `Error Lens` | Inline errors |
| `Path Intellisense` | Path autocomplete |
| `Project Manager` | Gestione progetti |
| `Todo Tree` | TODO highlights |
| `Bookmarks` | Segnalibri codice |

### Temi e Icone

| Estensione | Descrizione |
|------------|-------------|
| `One Dark Pro` | Tema popolare |
| `Dracula Official` | Tema dark |
| `Material Icon Theme` | Icone file |
| `vscode-icons` | Icone alternative |

### Linguaggi

| Estensione | Descrizione |
|------------|-------------|
| `Python` | Supporto Python |
| `Pylance` | Python language server |
| `ESLint` | JavaScript linter |
| `Prettier` | Code formatter |
| `C/C++` | Supporto C/C++ |
| `Java Extension Pack` | Supporto Java |
| `Go` | Supporto Go |
| `Rust Analyzer` | Supporto Rust |

### Web Development

| Estensione | Descrizione |
|------------|-------------|
| `Live Server` | Server locale |
| `Auto Rename Tag` | Rinomina tag HTML |
| `CSS Peek` | Peek CSS da HTML |
| `REST Client` | Test API |
| `Thunder Client` | API client |

### Docker & DevOps

| Estensione | Descrizione |
|------------|-------------|
| `Docker` | Supporto Docker |
| `Remote - SSH` | Sviluppo remoto |
| `Dev Containers` | Container development |
| `Kubernetes` | Supporto K8s |

---

## Workspace Settings

### .vscode/settings.json

```json
{
  "editor.tabSize": 4,
  "files.exclude": {
    "**/build": true,
    "**/__pycache__": true
  },
  "python.defaultInterpreterPath": "./venv/bin/python"
}
```

### .vscode/extensions.json

```json
{
  "recommendations": [
    "ms-python.python",
    "ms-python.vscode-pylance",
    "esbenp.prettier-vscode",
    "dbaeumer.vscode-eslint"
  ]
}
```

### .vscode/launch.json

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Python: Current File",
      "type": "debugpy",
      "request": "launch",
      "program": "${file}",
      "console": "integratedTerminal"
    },
    {
      "name": "Node: Current File",
      "type": "node",
      "request": "launch",
      "program": "${file}"
    }
  ]
}
```

### .vscode/tasks.json

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "Build",
      "type": "shell",
      "command": "npm run build",
      "group": {
        "kind": "build",
        "isDefault": true
      }
    },
    {
      "label": "Test",
      "type": "shell",
      "command": "npm test",
      "group": "test"
    }
  ]
}
```

---

## Snippets

### User Snippets

`Ctrl+Shift+P` > "Preferences: Configure User Snippets"

```json
// javascript.json
{
  "Console log": {
    "prefix": "cl",
    "body": ["console.log($1);"],
    "description": "Console log"
  },
  "Arrow function": {
    "prefix": "af",
    "body": [
      "const ${1:name} = (${2:params}) => {",
      "  $0",
      "};"
    ],
    "description": "Arrow function"
  },
  "Try catch": {
    "prefix": "tc",
    "body": [
      "try {",
      "  $1",
      "} catch (error) {",
      "  console.error(error);",
      "}"
    ]
  }
}
```

### Variabili Snippet

| Variable | Descrizione |
|----------|-------------|
| `$1, $2` | Tab stops |
| `$0` | Cursor finale |
| `${1:default}` | Placeholder |
| `${1|one,two|}` | Choice |
| `$TM_FILENAME` | Nome file |
| `$CURRENT_YEAR` | Anno |
| `$CLIPBOARD` | Clipboard |

---

## Multi-Root Workspace

### workspace.code-workspace

```json
{
  "folders": [
    {
      "name": "Frontend",
      "path": "./frontend"
    },
    {
      "name": "Backend",
      "path": "./backend"
    }
  ],
  "settings": {
    "files.exclude": {
      "**/node_modules": true
    }
  },
  "extensions": {
    "recommendations": [
      "esbenp.prettier-vscode"
    ]
  }
}
```

---

## Remote Development

```bash
# SSH
code --remote ssh-remote+user@host /path

# Container
code --remote dev-container+/path

# WSL
code --remote wsl+Ubuntu /path
```

---

## CLI

```bash
# Apri file/cartella
code .
code file.txt
code folder/

# Nuovo file
code --new-window

# Diff
code --diff file1 file2

# Vai a riga
code --goto file.txt:10

# Installa estensione
code --install-extension esbenp.prettier-vscode

# Lista estensioni
code --list-extensions

# Disabilita estensioni
code --disable-extensions
```

---

## Best Practices

- **Settings Sync**: Abilita sincronizzazione settings
- **Workspace**: Usa settings per-progetto
- **Snippets**: Crea snippet per pattern comuni
- **Keyboard**: Impara shortcuts
- **Extensions**: Installa solo necessarie

## Riferimenti

- [VSCode Documentation](https://code.visualstudio.com/docs)
- [Keyboard Shortcuts](https://code.visualstudio.com/docs/getstarted/keybindings)
- [Extension Marketplace](https://marketplace.visualstudio.com/VSCode)
