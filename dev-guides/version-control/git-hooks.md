# Git Hooks

## Scopo

Questa guida copre Git Hooks, script eseguiti automaticamente in risposta a eventi Git, utili per automatizzare controlli di qualita, formattazione e validazione.

## Prerequisiti

- Git installato
- Conoscenza base Git
- Shell scripting (Bash)

---

## Concetti Base

I Git Hooks sono script nella directory `.git/hooks/` eseguiti prima o dopo eventi Git specifici.

### Tipi di Hooks

| Hook | Quando | Uso Comune |
|------|--------|------------|
| `pre-commit` | Prima del commit | Linting, formatting |
| `prepare-commit-msg` | Prima dell'editor messaggio | Template messaggio |
| `commit-msg` | Dopo scrittura messaggio | Validazione messaggio |
| `post-commit` | Dopo il commit | Notifiche |
| `pre-push` | Prima del push | Test, build |
| `pre-rebase` | Prima del rebase | Validazioni |
| `post-merge` | Dopo il merge | Reinstall dipendenze |
| `post-checkout` | Dopo checkout | Setup ambiente |

---

## Creazione Hook

### Struttura Base

```bash
# .git/hooks/pre-commit
#!/bin/bash

echo "Running pre-commit hook..."

# Logica del hook
# Exit 0 = successo, permette l'operazione
# Exit 1 = fallimento, blocca l'operazione

exit 0
```

### Rendere Eseguibile

```bash
chmod +x .git/hooks/pre-commit
```

---

## Hook Comuni

### pre-commit

```bash
#!/bin/bash

echo "Running pre-commit checks..."

# Verifica file staged
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)

if [ -z "$STAGED_FILES" ]; then
    echo "No files staged"
    exit 0
fi

# Linting JavaScript/TypeScript
if echo "$STAGED_FILES" | grep -qE '\.(js|ts|jsx|tsx)$'; then
    echo "Running ESLint..."
    npx eslint $STAGED_FILES --fix
    if [ $? -ne 0 ]; then
        echo "ESLint failed. Fix errors before committing."
        exit 1
    fi
    git add $STAGED_FILES
fi

# Formatting Python
if echo "$STAGED_FILES" | grep -qE '\.py$'; then
    echo "Running Black..."
    black --check $STAGED_FILES
    if [ $? -ne 0 ]; then
        echo "Black formatting required."
        exit 1
    fi
fi

# Check for debug statements
if grep -rn "console.log\|debugger\|import pdb" $STAGED_FILES; then
    echo "Debug statements found!"
    exit 1
fi

echo "Pre-commit checks passed!"
exit 0
```

### commit-msg

```bash
#!/bin/bash

COMMIT_MSG_FILE=$1
COMMIT_MSG=$(cat "$COMMIT_MSG_FILE")

# Conventional Commits pattern
PATTERN="^(feat|fix|docs|style|refactor|perf|test|chore|ci|build|revert)(\(.+\))?: .{1,50}"

if ! echo "$COMMIT_MSG" | grep -qE "$PATTERN"; then
    echo "ERROR: Invalid commit message format!"
    echo ""
    echo "Expected format: <type>(<scope>): <description>"
    echo ""
    echo "Types: feat, fix, docs, style, refactor, perf, test, chore, ci, build, revert"
    echo ""
    echo "Examples:"
    echo "  feat(auth): add login functionality"
    echo "  fix(api): resolve null pointer exception"
    echo "  docs: update README"
    exit 1
fi

echo "Commit message valid!"
exit 0
```

### pre-push

```bash
#!/bin/bash

echo "Running pre-push checks..."

# Run tests
echo "Running tests..."
npm test
if [ $? -ne 0 ]; then
    echo "Tests failed! Push aborted."
    exit 1
fi

# Build check
echo "Checking build..."
npm run build
if [ $? -ne 0 ]; then
    echo "Build failed! Push aborted."
    exit 1
fi

# Prevent push to main/master directly
BRANCH=$(git rev-parse --abbrev-ref HEAD)
PROTECTED_BRANCHES="main master"

for protected in $PROTECTED_BRANCHES; do
    if [ "$BRANCH" = "$protected" ]; then
        echo "Direct push to $BRANCH is not allowed!"
        echo "Please create a pull request."
        exit 1
    fi
done

echo "Pre-push checks passed!"
exit 0
```

### post-merge

```bash
#!/bin/bash

echo "Running post-merge hook..."

# Check if package.json changed
CHANGED_FILES=$(git diff-tree -r --name-only --no-commit-id ORIG_HEAD HEAD)

if echo "$CHANGED_FILES" | grep -q "package.json"; then
    echo "package.json changed. Running npm install..."
    npm install
fi

if echo "$CHANGED_FILES" | grep -q "requirements.txt"; then
    echo "requirements.txt changed. Running pip install..."
    pip install -r requirements.txt
fi

if echo "$CHANGED_FILES" | grep -q "Gemfile"; then
    echo "Gemfile changed. Running bundle install..."
    bundle install
fi

exit 0
```

### prepare-commit-msg

```bash
#!/bin/bash

COMMIT_MSG_FILE=$1
COMMIT_SOURCE=$2
SHA1=$3

# Aggiungi branch name al messaggio
BRANCH=$(git rev-parse --abbrev-ref HEAD)

# Skip per merge, squash, amend
if [ -n "$COMMIT_SOURCE" ]; then
    exit 0
fi

# Estrai ticket da branch (es. feature/JIRA-123-description)
TICKET=$(echo "$BRANCH" | grep -oE '[A-Z]+-[0-9]+')

if [ -n "$TICKET" ]; then
    # Prepend ticket al messaggio
    sed -i.bak "1s/^/[$TICKET] /" "$COMMIT_MSG_FILE"
fi

exit 0
```

---

## Husky (Node.js)

### Installazione

```bash
npm install husky --save-dev
npx husky init
```

### Configurazione

```bash
# .husky/pre-commit
npm run lint
npm run test
```

### package.json

```json
{
  "scripts": {
    "prepare": "husky",
    "lint": "eslint src/",
    "test": "jest"
  }
}
```

---

## lint-staged

### Installazione

```bash
npm install lint-staged --save-dev
```

### Configurazione

```json
// package.json
{
  "lint-staged": {
    "*.{js,jsx,ts,tsx}": [
      "eslint --fix",
      "prettier --write"
    ],
    "*.{css,scss}": [
      "prettier --write"
    ],
    "*.py": [
      "black",
      "flake8"
    ]
  }
}
```

### Hook con Husky

```bash
# .husky/pre-commit
npx lint-staged
```

---

## pre-commit (Python)

### Installazione

```bash
pip install pre-commit
```

### Configurazione

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-added-large-files
  
  - repo: https://github.com/psf/black
    rev: 24.3.0
    hooks:
      - id: black
  
  - repo: https://github.com/pycqa/flake8
    rev: 7.0.0
    hooks:
      - id: flake8
  
  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.9.0
    hooks:
      - id: mypy
```

### Comandi

```bash
# Installa hooks
pre-commit install

# Esegui su tutti i file
pre-commit run --all-files

# Aggiorna hooks
pre-commit autoupdate

# Skip temporaneo
git commit --no-verify
```

---

## Condivisione Hooks

### Directory Personalizzata

```bash
# Configura directory hooks
git config core.hooksPath .githooks

# Struttura
.githooks/
├── pre-commit
├── commit-msg
└── pre-push
```

### Script di Setup

```bash
#!/bin/bash
# setup-hooks.sh

HOOKS_DIR=".githooks"

echo "Installing git hooks..."
git config core.hooksPath $HOOKS_DIR

chmod +x $HOOKS_DIR/*

echo "Git hooks installed!"
```

---

## Bypass Hooks

```bash
# Skip pre-commit e commit-msg
git commit --no-verify -m "Emergency fix"
git commit -n -m "Emergency fix"

# Skip pre-push
git push --no-verify
```

---

## Best Practices

- **Velocita**: Hooks veloci, no operazioni lunghe in pre-commit
- **Feedback**: Messaggi di errore chiari
- **Bypass**: Permetti --no-verify per emergenze
- **Condivisione**: Usa Husky o core.hooksPath
- **CI**: Non affidarti solo agli hooks, usa anche CI

## Riferimenti

- [Git Hooks Documentation](https://git-scm.com/docs/githooks)
- [Husky](https://typicode.github.io/husky/)
- [pre-commit](https://pre-commit.com/)
- [lint-staged](https://github.com/okonet/lint-staged)
