# PostgreSQL

## Scopo

Questa guida fornisce una panoramica su PostgreSQL, un database relazionale open source avanzato, coprendo installazione, comandi essenziali e best practice.

## Prerequisiti

- PostgreSQL installato
- Accesso al terminale
- Conoscenza base SQL

## Installazione

### Linux (Debian/Ubuntu)

```bash
sudo apt update
sudo apt install postgresql postgresql-contrib

# Avvia servizio
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

### Windows

Scarica l'installer da [postgresql.org](https://www.postgresql.org/download/windows/).

### macOS

```bash
brew install postgresql@15
brew services start postgresql@15
```

---

## Connessione

### psql CLI

```bash
# Connetti come postgres
sudo -u postgres psql

# Connetti a database specifico
psql -h localhost -U username -d database

# Con password
PGPASSWORD=password psql -h localhost -U user -d db
```

### Comandi psql

```sql
\l              -- Lista database
\c database     -- Connetti a database
\dt             -- Lista tabelle
\d table        -- Descrivi tabella
\du             -- Lista utenti
\dn             -- Lista schema
\df             -- Lista funzioni
\q              -- Esci
\?              -- Aiuto
\i file.sql     -- Esegui file SQL
```

---

## Gestione Database

### Creazione

```sql
-- Crea database
CREATE DATABASE mydb;

-- Con opzioni
CREATE DATABASE mydb
    OWNER = myuser
    ENCODING = 'UTF8'
    LC_COLLATE = 'en_US.UTF-8'
    LC_CTYPE = 'en_US.UTF-8';
```

### Eliminazione

```sql
DROP DATABASE mydb;
DROP DATABASE IF EXISTS mydb;
```

---

## Gestione Utenti

```sql
-- Crea utente
CREATE USER myuser WITH PASSWORD 'password';

-- Con privilegi
CREATE USER admin WITH PASSWORD 'pass' SUPERUSER CREATEDB;

-- Modifica password
ALTER USER myuser WITH PASSWORD 'newpassword';

-- Concedi privilegi
GRANT ALL PRIVILEGES ON DATABASE mydb TO myuser;
GRANT SELECT, INSERT ON table TO myuser;
GRANT USAGE ON SCHEMA public TO myuser;

-- Revoca
REVOKE ALL ON DATABASE mydb FROM myuser;

-- Elimina utente
DROP USER myuser;
```

---

## Tabelle

### Creazione

```sql
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT true
);

CREATE TABLE posts (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    title VARCHAR(200) NOT NULL,
    content TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);
```

### Modifica

```sql
-- Aggiungi colonna
ALTER TABLE users ADD COLUMN phone VARCHAR(20);

-- Modifica tipo
ALTER TABLE users ALTER COLUMN phone TYPE VARCHAR(30);

-- Rinomina
ALTER TABLE users RENAME COLUMN phone TO telephone;

-- Rimuovi colonna
ALTER TABLE users DROP COLUMN telephone;

-- Rinomina tabella
ALTER TABLE users RENAME TO app_users;
```

### Indici

```sql
-- Crea indice
CREATE INDEX idx_users_email ON users(email);
CREATE UNIQUE INDEX idx_users_username ON users(username);

-- Indice parziale
CREATE INDEX idx_active_users ON users(username) WHERE is_active = true;

-- Rimuovi
DROP INDEX idx_users_email;
```

---

## Query

### Select

```sql
-- Base
SELECT * FROM users;
SELECT username, email FROM users WHERE is_active = true;

-- Ordinamento
SELECT * FROM users ORDER BY created_at DESC;

-- Limite
SELECT * FROM users LIMIT 10 OFFSET 20;

-- Aggregazioni
SELECT COUNT(*) FROM users;
SELECT user_id, COUNT(*) as post_count FROM posts GROUP BY user_id;
```

### Join

```sql
-- Inner join
SELECT u.username, p.title
FROM users u
INNER JOIN posts p ON u.id = p.user_id;

-- Left join
SELECT u.username, p.title
FROM users u
LEFT JOIN posts p ON u.id = p.user_id;

-- Multiple join
SELECT u.username, p.title, c.content
FROM users u
JOIN posts p ON u.id = p.user_id
JOIN comments c ON p.id = c.post_id;
```

### Insert

```sql
-- Singolo
INSERT INTO users (username, email, password_hash)
VALUES ('mario', 'mario@email.com', 'hash123');

-- Multiplo
INSERT INTO users (username, email, password_hash) VALUES
    ('user1', 'user1@email.com', 'hash1'),
    ('user2', 'user2@email.com', 'hash2');

-- Con ritorno
INSERT INTO users (username, email, password_hash)
VALUES ('test', 'test@email.com', 'hash')
RETURNING id, username;
```

### Update

```sql
UPDATE users SET is_active = false WHERE id = 1;

UPDATE users
SET email = 'new@email.com', updated_at = NOW()
WHERE username = 'mario'
RETURNING *;
```

### Delete

```sql
DELETE FROM users WHERE id = 1;
DELETE FROM posts WHERE created_at < '2024-01-01';

-- Truncate (piu veloce)
TRUNCATE TABLE logs;
```

---

## Tipi di Dato

| Tipo | Descrizione |
|------|-------------|
| `SERIAL` | Auto-increment integer |
| `BIGSERIAL` | Auto-increment bigint |
| `INTEGER` | Intero 4 byte |
| `BIGINT` | Intero 8 byte |
| `NUMERIC(p,s)` | Precisione arbitraria |
| `VARCHAR(n)` | Stringa variabile |
| `TEXT` | Stringa illimitata |
| `BOOLEAN` | true/false |
| `TIMESTAMP` | Data e ora |
| `DATE` | Solo data |
| `JSON/JSONB` | Dati JSON |
| `UUID` | Identificatore unico |
| `ARRAY` | Array di valori |

---

## Funzioni Utili

```sql
-- Stringhe
SELECT UPPER('text'), LOWER('TEXT');
SELECT CONCAT(first_name, ' ', last_name);
SELECT LENGTH(username);
SELECT SUBSTRING(email FROM 1 FOR 5);

-- Data/ora
SELECT NOW(), CURRENT_DATE, CURRENT_TIME;
SELECT EXTRACT(YEAR FROM created_at);
SELECT created_at + INTERVAL '1 day';

-- JSON
SELECT data->>'name' FROM json_table;
SELECT data->'address'->>'city' FROM json_table;

-- Aggregate
SELECT COALESCE(nullable_col, 'default');
SELECT NULLIF(a, b);
```

---

## Transazioni

```sql
BEGIN;

UPDATE accounts SET balance = balance - 100 WHERE id = 1;
UPDATE accounts SET balance = balance + 100 WHERE id = 2;

-- Se tutto ok
COMMIT;

-- Se errore
ROLLBACK;
```

---

## Backup e Restore

```bash
# Dump database
pg_dump -U postgres mydb > backup.sql
pg_dump -U postgres -Fc mydb > backup.dump  # Custom format

# Dump solo struttura
pg_dump -U postgres --schema-only mydb > schema.sql

# Restore
psql -U postgres -d mydb < backup.sql
pg_restore -U postgres -d mydb backup.dump
```

---

## Best Practices

- **Indici**: Crea indici per colonne usate in WHERE/JOIN
- **Transactions**: Usa transazioni per operazioni multiple
- **Prepared statements**: Previeni SQL injection
- **Vacuum**: Esegui VACUUM regolarmente
- **Backup**: Backup automatici giornalieri

## Riferimenti

- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [PostgreSQL Tutorial](https://www.postgresqltutorial.com/)
