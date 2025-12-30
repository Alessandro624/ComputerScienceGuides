# GitHub Actions

## Scopo

Questa guida fornisce una panoramica di GitHub Actions, la piattaforma CI/CD integrata in GitHub per automatizzare build, test e deployment.

## Prerequisiti

- Repository GitHub
- Conoscenza base YAML
- Comprensione workflow CI/CD

---

## Concetti Base

| Termine | Descrizione |
|---------|-------------|
| Workflow | Processo automatizzato configurabile |
| Event | Trigger che avvia un workflow |
| Job | Set di step eseguiti sullo stesso runner |
| Step | Task singolo (action o comando) |
| Action | Applicazione riutilizzabile |
| Runner | Server che esegue i workflow |

---

## Struttura

```
repository/
└── .github/
    └── workflows/
        ├── ci.yml
        ├── deploy.yml
        └── release.yml
```

---

## Workflow Base

### Hello World

```yaml
# .github/workflows/hello.yml
name: Hello World

on: [push]

jobs:
  hello:
    runs-on: ubuntu-latest
    steps:
      - name: Print Hello
        run: echo "Hello, World!"
```

### CI Completo

```yaml
name: CI

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout
        uses: actions/checkout@v4
      
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'
      
      - name: Install dependencies
        run: npm ci
      
      - name: Run tests
        run: npm test
      
      - name: Build
        run: npm run build
```

---

## Events (Triggers)

### Push e Pull Request

```yaml
on:
  push:
    branches:
      - main
      - 'release/**'
    paths:
      - 'src/**'
      - '!src/**/*.md'
    tags:
      - 'v*'
  
  pull_request:
    branches: [main]
    types: [opened, synchronize, reopened]
```

### Schedule (Cron)

```yaml
on:
  schedule:
    - cron: '0 0 * * *'  # Ogni giorno a mezzanotte
    - cron: '0 */6 * * *'  # Ogni 6 ore
```

### Manual (workflow_dispatch)

```yaml
on:
  workflow_dispatch:
    inputs:
      environment:
        description: 'Environment to deploy'
        required: true
        default: 'staging'
        type: choice
        options:
          - staging
          - production
      debug:
        description: 'Enable debug mode'
        required: false
        type: boolean
        default: false
```

### Altri Events

```yaml
on:
  release:
    types: [published]
  
  issues:
    types: [opened, labeled]
  
  workflow_call:  # Workflow riutilizzabile
    inputs:
      config:
        required: true
        type: string
```

---

## Jobs

### Job Singolo

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Building..."
```

### Jobs Multipli

```yaml
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: npm test
  
  build:
    needs: test  # Dipendenza
    runs-on: ubuntu-latest
    steps:
      - run: npm run build
  
  deploy:
    needs: [test, build]  # Dipendenze multiple
    runs-on: ubuntu-latest
    steps:
      - run: ./deploy.sh
```

### Matrix

```yaml
jobs:
  test:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
        node: [18, 20, 22]
        exclude:
          - os: windows-latest
            node: 18
        include:
          - os: ubuntu-latest
            node: 20
            experimental: true
    
    steps:
      - uses: actions/setup-node@v4
        with:
          node-version: ${{ matrix.node }}
      - run: npm test
```

---

## Steps

### Comandi

```yaml
steps:
  - name: Single command
    run: echo "Hello"
  
  - name: Multi-line
    run: |
      echo "Line 1"
      echo "Line 2"
      npm install
  
  - name: Different shell
    run: Get-Process
    shell: pwsh
  
  - name: Working directory
    run: npm test
    working-directory: ./frontend
```

### Actions

```yaml
steps:
  # Action da marketplace
  - uses: actions/checkout@v4
  
  # Con parametri
  - uses: actions/setup-node@v4
    with:
      node-version: '20'
      cache: 'npm'
  
  # Action locale
  - uses: ./.github/actions/my-action
  
  # Action da altro repo
  - uses: owner/repo@v1
```

---

## Variabili e Secrets

### Environment Variables

```yaml
env:
  NODE_ENV: production

jobs:
  build:
    env:
      CI: true
    steps:
      - name: With env
        env:
          API_URL: https://api.example.com
        run: echo $API_URL
```

### Secrets

```yaml
steps:
  - name: Deploy
    env:
      API_KEY: ${{ secrets.API_KEY }}
    run: ./deploy.sh
  
  - name: Docker login
    run: |
      echo ${{ secrets.DOCKER_PASSWORD }} | docker login -u ${{ secrets.DOCKER_USERNAME }} --password-stdin
```

### Context Variables

```yaml
steps:
  - run: echo "Repo: ${{ github.repository }}"
  - run: echo "Branch: ${{ github.ref_name }}"
  - run: echo "SHA: ${{ github.sha }}"
  - run: echo "Actor: ${{ github.actor }}"
  - run: echo "Event: ${{ github.event_name }}"
  - run: echo "Run ID: ${{ github.run_id }}"
```

---

## Outputs

### Tra Steps

```yaml
steps:
  - name: Set output
    id: step1
    run: echo "version=1.0.0" >> $GITHUB_OUTPUT
  
  - name: Use output
    run: echo "Version is ${{ steps.step1.outputs.version }}"
```

### Tra Jobs

```yaml
jobs:
  job1:
    runs-on: ubuntu-latest
    outputs:
      version: ${{ steps.get_version.outputs.version }}
    steps:
      - id: get_version
        run: echo "version=1.0.0" >> $GITHUB_OUTPUT
  
  job2:
    needs: job1
    runs-on: ubuntu-latest
    steps:
      - run: echo "Version is ${{ needs.job1.outputs.version }}"
```

---

## Condizioni

```yaml
steps:
  - name: Only on main
    if: github.ref == 'refs/heads/main'
    run: echo "On main branch"
  
  - name: Only on PR
    if: github.event_name == 'pull_request'
    run: echo "This is a PR"
  
  - name: On success
    if: success()
    run: echo "Previous steps succeeded"
  
  - name: On failure
    if: failure()
    run: echo "Something failed"
  
  - name: Always run
    if: always()
    run: echo "Cleanup"
  
  - name: Complex condition
    if: |
      github.event_name == 'push' &&
      contains(github.event.head_commit.message, '[deploy]')
    run: ./deploy.sh
```

---

## Artifacts e Cache

### Artifacts

```yaml
steps:
  - name: Build
    run: npm run build
  
  - name: Upload artifact
    uses: actions/upload-artifact@v4
    with:
      name: build-output
      path: dist/
      retention-days: 5

  # In altro job
  - name: Download artifact
    uses: actions/download-artifact@v4
    with:
      name: build-output
      path: dist/
```

### Cache

```yaml
steps:
  - name: Cache node modules
    uses: actions/cache@v4
    with:
      path: ~/.npm
      key: ${{ runner.os }}-node-${{ hashFiles('**/package-lock.json') }}
      restore-keys: |
        ${{ runner.os }}-node-
  
  - name: Install
    run: npm ci
```

---

## Esempi Completi

### Python CI

```yaml
name: Python CI

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ['3.10', '3.11', '3.12']
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
          cache: 'pip'
      
      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt
          pip install pytest pytest-cov
      
      - name: Test with pytest
        run: pytest --cov=src --cov-report=xml
      
      - name: Upload coverage
        uses: codecov/codecov-action@v4
        with:
          file: coverage.xml
```

### Docker Build & Push

```yaml
name: Docker

on:
  push:
    tags: ['v*']

jobs:
  docker:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Docker meta
        id: meta
        uses: docker/metadata-action@v5
        with:
          images: ghcr.io/${{ github.repository }}
          tags: |
            type=semver,pattern={{version}}
            type=sha
      
      - name: Login to GHCR
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      
      - name: Build and push
        uses: docker/build-push-action@v5
        with:
          context: .
          push: true
          tags: ${{ steps.meta.outputs.tags }}
```

---

## Best Practices

- **Versioning**: Usa versioni specifiche per actions (`@v4` non `@main`)
- **Secrets**: Mai hardcodare credenziali
- **Cache**: Usa cache per velocizzare build
- **Matrix**: Testa su multiple versioni/OS
- **Timeout**: Imposta timeout per evitare job bloccati

## Riferimenti

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Actions Marketplace](https://github.com/marketplace?type=actions)
- [Workflow Syntax](https://docs.github.com/en/actions/reference/workflow-syntax-for-github-actions)
