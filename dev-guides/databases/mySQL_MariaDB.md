# MySQL / MariaDB - Guida rapida

## Accesso

Per accedere a MySQL o MariaDB, utilizzare il comando:

```bash
mysql -u utente -p password -P porta
```

## Apertura/Chiusura Servizio MariaDB

Per gestire il servizio MariaDB, eseguire i seguenti comandi come amministratore:

```bash
net stop MariaDB
net start MariaDB
```

## Creazione Utente

Per creare un nuovo utente in MySQL:

```sql
CREATE USER nome@localhost;
SET PASSWORD FOR nome@localhost=PASSWORD(password);
```

Oppure:

```sql
CREATE USER nome@localhost IDENTIFIED BY password;
```

## Eliminazione Utente

Per eliminare un utente:

```sql

DROP USER nome@localhost;
```

## Variabili Globali

Per visualizzare le variabili globali:

```sql
SHOW GLOBAL VARIABLES [LIKE 'pattern'];
```

Per visualizzare la variabile dell'event scheduler:

```sql
SHOW GLOBAL VARIABLES LIKE '%event%';
```

Se l'event scheduler è disabilitato, attivarlo:

```sql
SET GLOBAL event_scheduler = ON;
```

Se si vuole disabilitare:

```sql
SET GLOBAL event_scheduler = OFF;
```

Per mostrare tutti i processi attivi in MySQL:

```sql
SHOW PROCESSLIST;
```

## Creazione Database

Per creare un database:

```sql
CREATE {DATABASE | SCHEMA} [IF NOT EXISTS] db_name [create_specification [, create_specification] ...];
```

`create_specification` include:

- `[DEFAULT] CHARACTER SET charset_name`
- `[DEFAULT] COLLATE collation_name`

## Eliminazione Database

Per eliminare un database:

```sql
DROP {DATABASE | SCHEMA} [IF EXISTS] db_name;
```

## Privilegi

Per concedere privilegi su un database:

```sql
GRANT SELECT, INSERT, UPDATE, DELETE ON nome_database.* TO nome@localhost IDENTIFIED BY password;
GRANT ALTER ON nome_database.* TO nome@localhost;
```

Oppure:

```sql
GRANT ALL PRIVILEGES ON nome_database.* TO nome@localhost;
```

Per selezionare un database:

```sql
SHOW DATABASES;
USE nome_database;
```

## Backup Database

### Esegui Backup

- Backup di un singolo database:

```bash
mysqldump -u user -p db_da_copiare > backup.sql
```

- Backup di più database:

```bash
mysqldump -u user -p --databases dbuno dbdue dbtre > backup_di_tre_db.sql
```

- Backup di tutti i database:

```bash
mysqldump -u user -p --all-databases > backup_tutti_i_db.sql
```

- Backup di una singola tabella:

```bash
mysqldump -u user -p db_da_copiare nome_tabella > backup.sql
```

- Backup di singole tabelle con clausola WHERE:

```bash
mysqldump -u user -p --where="id > 10" db_da_copiare nome_tabella > backup.sql
```

- Backup di più tabelle:

```bash
mysqldump -u user -p db_da_copiare nome_tabella1 nome_tabella2 nome_tabella3 > backup.sql
```

- Comprimere il backup:

```bash
mysqldump -u user -p db_da_copiare | gzip -9 > backup.sql.gz
```

### Ripristino Database

- Per ripristinare un database da un backup:

```bash
mysql -u user -p < backup.sql
```

- Per ripristinare più database:

```bash
mysql -u user -p < backup_tutti_i_db.sql
```

- Se nel backup è stata usata l'opzione `--no-create-db`, creare manualmente i database prima del ripristino.

- Per ripristinare un singolo database da un backup di più database:

```bash
mysql -u user -p --one-database nome_del_db < backup_tutti_i_db.sql
```

- Per ripristinare un backup compresso con GZIP:

```bash
gunzip < backup.sql.gz | mysql -u user -p
```

## Creazione Tabella

Per creare una tabella:

```sql
CREATE [TEMPORARY] TABLE [IF NOT EXISTS] tbl_name [(create_definition,...)] [table_options] [select_statement];
```

Alcune opzioni di `create_definition` includono:

- Definizione di colonna
- PRIMARY KEY
- FOREIGN KEY
- CHECK

### Definizione Colonne

Esempio di una definizione di colonna:

```sql
col_name type [NOT NULL | NULL] [DEFAULT default_value] [AUTO_INCREMENT] [[PRIMARY] KEY] [COMMENT 'string']
```

I tipi di dato supportati includono:

- `TINYINT`, `SMALLINT`, `MEDIUMINT`, `INT`, `BIGINT`
- `FLOAT`, `DOUBLE`, `DECIMAL`
- `DATE`, `TIME`, `TIMESTAMP`, `DATETIME`
- `VARCHAR`, `TEXT`, `BLOB`

## Eliminazione/Rinominazione Tabella

Per eliminare una tabella:

```sql
DROP [TEMPORARY] TABLE [IF EXISTS] tbl_name [, tbl_name] ... [RESTRICT | CASCADE];
```

Per rinominare una tabella:

```sql
RENAME TABLE tbl_name TO new_tbl_name [, tbl_name2 TO new_tbl_name2] ...;
```

## Creazione/Eliminazione Index/Key

Per creare un indice:

```sql
CREATE [UNIQUE|FULLTEXT|SPATIAL] INDEX index_name [index_type] ON tbl_name (index_col_name,...);
```

Per eliminare un indice:

```sql
DROP INDEX index_name ON tbl_name;
```

## Visualizzazione Tabella

Per visualizzare la struttura di una tabella:

```sql
DESCRIBE table;
```

## Operazioni di Modifica Dati

### Inserimento

Per inserire dati in una tabella:

```sql
INSERT INTO table_name [(table_column[,...])] VALUES (valori per colonna)[,...];
```

### Aggiornamento

Per aggiornare dati in una tabella:

```sql
UPDATE table_name SET column='...' [WHERE condition];
```

### Eliminazione

Per eliminare dati da una tabella:

```sql
DELETE FROM table_name [WHERE condition];
```

## Modifica Delimitatore delle ISTRUZIONI

Per cambiare il delimitatore delle istruzioni SQL:

```sql
DELIMITER //
-- corpo del comando
DELIMITER ;
```

## Sintassi Trigger

Per creare un trigger:

```sql
[DEFINER = { user | CURRENT_USER }] 
TRIGGER trigger_name trigger_time trigger_event 
ON tbl_name FOR EACH ROW trigger_body;
```

## Stored Procedure

### Creazione

Per creare una stored procedure:

```sql
CREATE [DEFINER = { user | CURRENT_USER }] 
PROCEDURE sp_name ([proc_parameter[,...]]) 
[characteristic ...] routine_body;
```

### Modifica

Per visualizzare lo stato delle procedure:

```sql
SHOW PROCEDURE STATUS;
SHOW CREATE PROCEDURE <nome>;
```

Per eliminare una stored procedure:

```sql
DROP PROCEDURE <nome>;
```

## Stored Function

### Creazione Stored Function

Per creare una stored function:

```sql
CREATE [DEFINER = { user | CURRENT_USER }] 
FUNCTION sp_name ([func_parameter[,...]]) 
RETURNS type 
[characteristic ...] routine_body;
```

## Funzioni e Operatori Logici

Per consultare le funzioni e gli operatori logici disponibili in MariaDB:
[Funzioni e Operatori Logici MariaDB](https://mariadb.com/kb/it/funzioni-e-operatori/)

## View

### Creazione View

Per creare o sostituire una view:

```sql
CREATE [OR REPLACE] VIEW [db_name.]view_name [(column_list)] 
AS select-statement;
```

## Transazioni

### Esecuzione di Transazioni

Per avviare una transazione:

```sql
START TRANSACTION;
-- Esegui una serie di query all'interno della transazione
INSERT INTO table1 (col1, col2) VALUES ('valore1', 'valore2');
SAVEPOINT savepoint1;  -- Crea un savepoint
UPDATE table2 SET col1 = 'nuovo valore' WHERE id = 1;
IF ROW_COUNT() > 0 THEN
    DELETE FROM table3 WHERE col1 = 'valore da eliminare';
ELSE
    ROLLBACK TO savepoint1;  -- Torna al savepoint in caso di errore
END IF;
COMMIT;  -- Conferma la transazione
ROLLBACK;  -- Annulla la transazione in caso di errori
```

## Eventi

### Creazione Evento

Per creare un evento:

```sql
CREATE [DEFINER = { user | CURRENT_USER }] 
EVENT [IF NOT EXISTS] event_name 
ON SCHEDULE schedule 
[ON COMPLETION [NOT] PRESERVE] 
[ENABLE | DISABLE | DISABLE ON SLAVE] 
[COMMENT 'comment'] 
DO event_body;
```

Per visualizzare la creazione di un evento:

```sql
SHOW CREATE EVENT <event_name>\G
```

Per eliminare un evento:

```sql
DROP EVENT [IF EXISTS] event_name;
```
