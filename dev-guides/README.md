# Dev Guides

Questa cartella contiene guide pratiche sugli strumenti e le pratiche di sviluppo e amministrazione.

## Sotto-cartelle

- `build-tools/` - Strumenti di build (Maven, Gradle, CMake, npm/Yarn/pnpm)
- `ci-cd/` - Continuous Integration e Deployment (GitHub Actions, GitLab CI)
- `containerization/` - Containerizzazione (Docker, Kubernetes)
- `databases/` - Database (MySQL, MariaDB, PostgreSQL)
- `debugging/` - Strumenti di debugging (Valgrind, Logging)
- `documentation/` - Documentazione e API (Doxygen, REST API, VSCode)
- `frameworks/` - Framework applicativi (Spring Boot)
- `os/` - Sistemi operativi e shell (Linux, Bash, SSH, Regex)
- `parallel-computing/` - Programmazione parallela (MPI)
- `testing/` - Framework di test (JUnit, pytest)
- `version-control/` - Controllo versione (Git, Git Hooks)

---

## Build Tools

- [Maven](build-tools/maven.md): guida rapida a Maven, struttura del progetto e gestione dipendenze/plugin.
- [Gradle](build-tools/gradle.md): build tool moderno per Java/Kotlin con DSL Groovy e Kotlin.
- [CMake](build-tools/cmake.md): sistema di build cross-platform per progetti C/C++.
- [Makefile](build-tools/makefile.md): automazione build con GNU Make.
- [npm / Yarn / pnpm](build-tools/npm-yarn-pnpm.md): package manager JavaScript/Node.js a confronto.

## CI/CD

- [GitHub Actions](ci-cd/github-actions.md): automazione workflow CI/CD integrata in GitHub.
- [GitLab CI](ci-cd/gitlab-ci.md): pipeline CI/CD con GitLab, stages e jobs.

## Containerization

- [Docker](containerization/docker.md): comandi e esempi per gestire immagini, container, volumi, reti e Compose.
- [Kubernetes](containerization/kubernetes.md): orchestrazione container, deployment e gestione cluster.

## Databases

- [MySQL - MariaDB](databases/mySQL_MariaDB.md): comandi essenziali, backup e gestione per MySQL/MariaDB.
- [PostgreSQL](databases/postgresql.md): database relazionale avanzato, query e amministrazione.

## Debugging

- [Valgrind](debugging/valgrind.md): uso di Valgrind per trovare memory leak e profilare l'applicazione.
- [Logging](debugging/logging.md): best practices di logging in Python, Java, JavaScript e Go.

## Documentation

- [Doxygen](documentation/doxygen.md): introduzione a Doxygen e generazione automatica della documentazione dal codice.
- [REST API Design](documentation/rest-api-design.md): best practices per progettare API RESTful.
- [VSCode](documentation/vscode.md): configurazione, shortcuts e estensioni per Visual Studio Code.

## Frameworks

- [Spring Boot](frameworks/spring-boot.md): framework Java per applicazioni enterprise-ready con Spring.

## OS / Shell

- [Linux](os/linux.md): comandi Linux utili, setup WSL e consigli per sviluppo su Linux/WSL.
- [Bash Scripting](os/bash-scripting.md): automazione con script Bash, variabili, cicli e funzioni.
- [Python Environments](os/python-environments.md): gestione ambienti virtuali con venv, conda e Poetry.
- [SSH](os/ssh.md): connessioni remote sicure, chiavi, tunneling e configurazione.
- [Regex](os/regex.md): espressioni regolari per pattern matching e text processing.

## Parallel Computing

- [MPI](parallel-computing/mpi.md): introduzione a MPI per programmazione parallela e esempi di uso.

## Testing

- [JUnit](testing/junit.md): guida rapida a JUnit 5 e best practice per i test.
- [pytest](testing/pytest.md): framework di testing Python con fixtures, parametrizzazione e coverage.

## Version Control

- [Git](version-control/git.md): elenco dei comandi Git piu utili per workflow, branching e ripristino.
- [Git Hooks](version-control/git-hooks.md): automazione con pre-commit, commit-msg e pre-push hooks.

---

Aggiungi nuove guide seguendo il [TEMPLATE](../TEMPLATE.md).
