# npm / Yarn / pnpm

## Scopo

Questa guida fornisce una panoramica dei principali package manager per JavaScript/Node.js: npm, Yarn e pnpm, confrontandone funzionalita e comandi.

## Prerequisiti

- Node.js installato
- Terminale/Command line

---

## Confronto

| Feature | npm | Yarn | pnpm |
|---------|-----|------|------|
| Velocita | Medio | Veloce | Molto veloce |
| Disk space | Alto | Alto | Basso |
| Lock file | package-lock.json | yarn.lock | pnpm-lock.yaml |
| Workspaces | Si | Si | Si |
| Plug'n'Play | No | Si | No |

---

## npm

### Installazione

npm viene installato con Node.js.

```bash
# Verifica versione
npm --version

# Aggiorna npm
npm install -g npm@latest
```

### Comandi Principali

```bash
# Inizializza progetto
npm init
npm init -y  # Skip prompts

# Installa dipendenze
npm install
npm i  # Alias

# Aggiungi dipendenza
npm install lodash
npm i lodash

# Dev dependency
npm install --save-dev jest
npm i -D jest

# Global
npm install -g typescript

# Versione specifica
npm install lodash@4.17.21
npm install lodash@^4.0.0  # Range

# Rimuovi
npm uninstall lodash
npm remove lodash

# Aggiorna
npm update
npm update lodash

# Outdated
npm outdated

# Audit
npm audit
npm audit fix

# Run script
npm run build
npm run test
npm start  # Shortcut per npm run start

# Lista pacchetti
npm list
npm list --depth=0

# Info pacchetto
npm info lodash

# Cerca pacchetti
npm search express

# Cache
npm cache clean --force

# Link locale
npm link
npm link package-name
```

### package.json

```json
{
  "name": "my-project",
  "version": "1.0.0",
  "description": "Project description",
  "main": "index.js",
  "scripts": {
    "start": "node index.js",
    "dev": "nodemon index.js",
    "build": "tsc",
    "test": "jest",
    "lint": "eslint src/",
    "prepare": "husky install"
  },
  "dependencies": {
    "express": "^4.18.2",
    "lodash": "~4.17.21"
  },
  "devDependencies": {
    "jest": "^29.7.0",
    "typescript": "^5.3.0"
  },
  "engines": {
    "node": ">=18.0.0"
  },
  "keywords": ["example"],
  "author": "Name <email@example.com>",
  "license": "MIT"
}
```

### .npmrc

```ini
# .npmrc
registry=https://registry.npmjs.org/
save-exact=true
engine-strict=true

# Private registry
@mycompany:registry=https://npm.mycompany.com/

# Auth token
//npm.mycompany.com/:_authToken=${NPM_TOKEN}
```

---

## Yarn

### Installazione

```bash
# Via npm
npm install -g yarn

# Via Corepack (Node.js 16.10+)
corepack enable
corepack prepare yarn@stable --activate
```

### Comandi Principali

```bash
# Versione
yarn --version

# Inizializza
yarn init
yarn init -y

# Installa dipendenze
yarn
yarn install

# Aggiungi dipendenza
yarn add lodash

# Dev dependency
yarn add --dev jest
yarn add -D jest

# Global
yarn global add typescript

# Versione specifica
yarn add lodash@4.17.21

# Rimuovi
yarn remove lodash

# Aggiorna
yarn upgrade
yarn upgrade lodash
yarn upgrade-interactive  # Interattivo

# Outdated
yarn outdated

# Run script
yarn build
yarn test
yarn start

# Lista
yarn list
yarn list --depth=0

# Info
yarn info lodash

# Why (perche installato)
yarn why lodash

# Cache
yarn cache clean

# Link
yarn link
yarn link package-name

# Workspaces
yarn workspaces info
yarn workspace package-name add lodash
```

### Yarn Berry (v2+)

```bash
# Aggiorna a Berry
yarn set version berry

# Plugin
yarn plugin import typescript

# PnP
yarn config set nodeLinker pnp
yarn install
```

---

## pnpm

### Installazione

```bash
# Via npm
npm install -g pnpm

# Via Corepack
corepack enable
corepack prepare pnpm@latest --activate

# Standalone
curl -fsSL https://get.pnpm.io/install.sh | sh -
```

### Comandi Principali

```bash
# Versione
pnpm --version

# Inizializza
pnpm init

# Installa dipendenze
pnpm install
pnpm i

# Aggiungi dipendenza
pnpm add lodash

# Dev dependency
pnpm add --save-dev jest
pnpm add -D jest

# Global
pnpm add -g typescript

# Versione specifica
pnpm add lodash@4.17.21

# Rimuovi
pnpm remove lodash

# Aggiorna
pnpm update
pnpm update lodash
pnpm update --interactive

# Outdated
pnpm outdated

# Run script
pnpm build
pnpm test
pnpm start

# Lista
pnpm list
pnpm list --depth=0

# Why
pnpm why lodash

# Store
pnpm store status
pnpm store prune

# Import da npm/yarn
pnpm import

# Workspaces
pnpm -r install  # Recursive
pnpm --filter package-name add lodash
```

### pnpm-workspace.yaml

```yaml
packages:
  - 'packages/*'
  - 'apps/*'
  - '!**/test/**'
```

---

## Workspaces (Monorepo)

### npm Workspaces

```json
// package.json (root)
{
  "name": "my-monorepo",
  "workspaces": [
    "packages/*",
    "apps/*"
  ]
}
```

```bash
# Comandi workspace
npm install -w packages/shared lodash
npm run build -w packages/shared
npm run build --workspaces
npm run test --workspaces --if-present
```

### Yarn Workspaces

```json
// package.json (root)
{
  "workspaces": [
    "packages/*"
  ]
}
```

```bash
yarn workspace @myapp/shared add lodash
yarn workspaces foreach run build
```

### pnpm Workspaces

```yaml
# pnpm-workspace.yaml
packages:
  - 'packages/*'
```

```bash
pnpm --filter @myapp/shared add lodash
pnpm -r run build
```

---

## Versioning

```
^1.2.3  # Compatible: >=1.2.3 <2.0.0
~1.2.3  # Approximately: >=1.2.3 <1.3.0
1.2.3   # Exact version
>=1.2.3 # Greater or equal
<2.0.0  # Less than
1.2.x   # Any patch version
*       # Any version
```

---

## Pubblicazione

```bash
# Login
npm login
npm whoami

# Pubblica
npm publish
npm publish --access public  # Scoped package

# Version bump
npm version patch  # 1.0.0 -> 1.0.1
npm version minor  # 1.0.0 -> 1.1.0
npm version major  # 1.0.0 -> 2.0.0

# Deprecate
npm deprecate package@version "message"

# Unpublish (entro 72h)
npm unpublish package@version
```

---

## Best Practices

- **Lock files**: Sempre commit dei lock file
- **Exact versions**: Usa `save-exact` per riproducibilita
- **Security**: Esegui `npm audit` regolarmente
- **Clean install**: Usa `npm ci` in CI/CD
- **pnpm**: Preferisci per risparmio spazio

## Riferimenti

- [npm Documentation](https://docs.npmjs.com/)
- [Yarn Documentation](https://yarnpkg.com/)
- [pnpm Documentation](https://pnpm.io/)
