# Maven - Guida Rapida

## Installazione
Per installare Maven, scarica l'ultima versione dal sito ufficiale [Apache Maven](https://maven.apache.org/download.cgi) e decomprimila in una directory a tua scelta. Successivamente, aggiungi il percorso della directory `bin` alla variabile d'ambiente `PATH`.

Per verificare che Maven sia stato installato correttamente, esegui:
```bash
mvn -v
```

## Struttura di un Progetto Maven
Un progetto Maven è organizzato in una struttura di directory standard. Ecco la struttura di base:

```
nome-progetto
│
├── src
│   ├── main
│   │   ├── java               # Codice sorgente Java
│   │   └── resources          # Risorse (file di configurazione, etc.)
│   ├── test
│   │   ├── java               # Test di unità
│   │   └── resources          # Risorse di test
├── target                     # Directory di output (compilazione e pacchetti)
├── pom.xml                    # File di configurazione Maven
```

## pom.xml
Il file `pom.xml` è il cuore di ogni progetto Maven. Contiene tutte le informazioni di configurazione e le dipendenze del progetto. Un esempio di `pom.xml` di base:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>com.example</groupId>
    <artifactId>nome-progetto</artifactId>
    <version>1.0-SNAPSHOT</version>
    
    <dependencies>
        <!-- Aggiungi le dipendenze qui -->
    </dependencies>

    <build>
        <plugins>
            <!-- Aggiungi i plugin di costruzione qui -->
        </plugins>
    </build>
</project>
```

## Costruzione del Progetto

### Esegui Build
Per costruire il progetto, esegui:
```bash
mvn clean install
```
- `clean`: rimuove la cartella `target` (se esiste) prima di iniziare una nuova compilazione.
- `install`: compila il progetto e copia l'artefatto (file JAR, WAR, etc.) nella repository locale di Maven.

### Esegui il Test
Per eseguire i test di unità:
```bash
mvn test
```

### Esegui la compilazione
Per compilare il progetto senza eseguire i test:
```bash
mvn compile
```

### Generare il pacchetto (JAR/WAR)
Per generare un pacchetto eseguibile:
```bash
mvn package
```

## Gestione delle Dipendenze
Le dipendenze vengono gestite nel file `pom.xml` sotto il tag `<dependencies>`. Un esempio di dipendenza per JUnit:

```xml
<dependencies>
    <dependency>
        <groupId>junit</groupId>
        <artifactId>junit</artifactId>
        <version>4.13.1</version>
        <scope>test</scope>
    </dependency>
</dependencies>
```

Per aggiungere una dipendenza al progetto, puoi trovare le informazioni su [Maven Central Repository](https://search.maven.org/).

### Gestione delle Versioni
Puoi specificare la versione della dipendenza, come nel caso di JUnit sopra, o utilizzare un intervallo di versioni per una maggiore flessibilità:

```xml
<dependency>
    <groupId>com.example</groupId>
    <artifactId>nome-dipendenza</artifactId>
    <version>[1.0,2.0)</version>
</dependency>
```

## Plugin

### Configurazione di un Plugin
Maven utilizza i plugin per eseguire diverse fasi di un ciclo di vita di costruzione. Per configurare un plugin, aggiungi la sezione `<plugins>` nel tag `<build>` del file `pom.xml`:

```xml
<build>
    <plugins>
        <plugin>
            <groupId>org.apache.maven.plugins</groupId>
            <artifactId>maven-compiler-plugin</artifactId>
            <version>3.8.1</version>
            <configuration>
                <source>1.8</source>
                <target>1.8</target>
            </configuration>
        </plugin>
    </plugins>
</build>
```

### Plugin per Eseguire Test
Per eseguire i test di unità con il plugin `maven-surefire-plugin`:

```xml
<build>
    <plugins>
        <plugin>
            <groupId>org.apache.maven.plugins</groupId>
            <artifactId>maven-surefire-plugin</artifactId>
            <version>2.22.2</version>
        </plugin>
    </plugins>
</build>
```

## Profilo
Un profilo consente di configurare diverse impostazioni di build, come la configurazione di ambiente o destinazione di distribuzione, che possono essere attivate o disattivate. Ecco un esempio di un profilo di test in `pom.xml`:

```xml
<profiles>
    <profile>
        <id>test</id>
        <properties>
            <maven.test.skip>true</maven.test.skip>
        </properties>
    </profile>
</profiles>
```

Puoi attivare un profilo con il comando:
```bash
mvn clean install -P test
```

## Repository

### Aggiungere una Repository
Per aggiungere una repository personalizzata, usa il tag `<repositories>`:

```xml
<repositories>
    <repository>
        <id>nome-repository</id>
        <url>https://repo.example.com/maven2</url>
    </repository>
</repositories>
```

### Utilizzare una Repository Locale
Puoi usare una repository locale per archiviare artefatti personali o di terze parti. La configurazione si effettua nel file `settings.xml` di Maven (tipicamente in `~/.m2/settings.xml`).

```xml
<localRepository>/path/to/local/repository</localRepository>
```

## Esecuzione di Comandi Personalizzati
Per eseguire comandi Maven personalizzati, puoi scrivere un ciclo di vita specifico nel tuo file `pom.xml`, per esempio:

```xml
<build>
    <plugins>
        <plugin>
            <groupId>org.apache.maven.plugins</groupId>
            <artifactId>maven-exec-plugin</artifactId>
            <version>3.0.0</version>
            <executions>
                <execution>
                    <goals>
                        <goal>java</goal>
                    </goals>
                </execution>
            </executions>
        </plugin>
    </plugins>
</build>
```

Per eseguire il comando personalizzato:
```bash
mvn exec:java
```

## Esegui un Semplice Comando
Maven offre anche comandi per la gestione del progetto, per esempio:

- Visualizzare informazioni sul progetto:
  ```bash
  mvn help:effective-pom
  ```

- Visualizzare la versione di Maven:
  ```bash
  mvn --version
  ```
