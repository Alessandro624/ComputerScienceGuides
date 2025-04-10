# **DOCKER**

## Versione Docker

```sh
docker version
```

**Opzioni:**

- `--format`: specifica il formato di output (JSON, tabella, ecc..)

## Informazioni Docker

```sh
docker info
docker system info
```

## Elenco comandi disponibili o aiuto su comando specifico

```sh
docker help
docker help <comando>
```

## Pulisce immagini, container e volumi inutilizzati

```sh
docker system prune
```

**Opzioni:**

- `-a`: rimuove anche le immagini non utilizzate

## Ricerca all'interno di Docker Hub i repository che contengono una stringa

```sh
docker search <stringa>
```

---

## **IMMAGINI**

## Visualizzazione immagini

```sh
docker image ls
docker images
```

**Opzioni:**

- `-a`: mostra tutte le immagini, incluse quelle intermedie
- `--filter`: filtra le immagini in base a criteri specifici
- `--format`: formatta l'output in base ad un template personalizzato

## Pulling di un'immagine da un registro

```sh
docker image pull <immagine>:<tag>
docker pull <immagine>:<tag>
```

**Opzioni:**

- `--all-tags`: scarica tutte le versioni di un'immagine
- `--platform`: specifica la piattaforma (es. linux/amd64)

## Restituzione ID numerico immagine/i

```sh
docker images -q
```

## Filtro di selezione per le immagini

```sh
docker images -f
```

## Rimozione immagine in ambiente Docker locale

```sh
docker rmi <immagine>
docker image rm <immagine>
```

**Opzioni:**

- `-f`: per forzare la rimozione

## Rimozione immagini non utilizzate

```sh
docker image prune
```

## Informazioni dettagliate su un'immagine Docker

```sh
docker inspect <immagine>:<tag>
```

## Cronologia di un'immagine

```sh
docker history <immagine>
```

## Rinominazione immagine o assegnazione nuovo tag

```sh
docker tag <immagine> <nuovo_nome>
```

## Creazione di un'immagine da un Dockerfile

```sh
docker build -t <immagine>:<tag> .
```

**Opzioni:**

- `-t`: assegna nome e tag
- `--no-cache`: costruisce l'immagine ignorando la cache

## Salvare un'immagine in un file tar

```sh
docker save -o <file.tar> <immagine>
```

## Caricare un'immagine da un file tar

```sh
docker load -i <file.tar>
```

## Pubblicare un'immagine su Docker Hub o un registry

```sh
docker push <repository>/<image>:<tag>
```

---

## **CONTAINER**

## Rimozione container

```sh
docker rm <container>
```

## Esecuzione container a partire da un'immagine

```sh
docker container run <immagine> <servizio>
docker run <immagine>
```

**Opzioni:**

- `-d`: avvia in background
- `--name`: assegna un nome al container
- `-it`: esegui in modalità interattiva
- `--rm`: cancella il container alla chiusura
- `-p HOST:CONTAINER`: mappa le porte
- `-v HOST:CONTAINER`: monta un volume
- `-e VAR=VAL`: imposta variabili d'ambiente
- `--memory=512m`: limita la RAM
- `--cpus=1`: limita la CPU

## Rientro terminale container

```sh
docker container exec -it <container> bash
```

## Elencare i container

```sh
docker ps
```

**Opzioni:**

- `-a`: anche quelli stoppati
- `-q`: mostra solo gli ID

## Avviare un container stoppato

```sh
docker container start <container>
docker start <container>
```

**Opzioni:**

- `-i`: interattivo

## Stoppare un container

```sh
docker container stop <container>
docker stop <container>
```

## Riavviare un container

```sh
docker container restart <container>
docker restart <container>
```

## Rimozione container stoppati

```sh
docker container prune
```

## Avviare container in background

```sh
docker run -d -it <immagine> <servizio>
```

## Rientrare nel container

```sh
docker attach <container>
docker container exec -it <container> <servizio>
```

## Visualizzare i processi del container

```sh
docker top <container>
```

## Visualizzare statistiche del container

```sh
docker stats <container>
```

## Visualizzare i logs del container

```sh
docker container logs <container>
```

---

## **VOLUMI**

## Creazione volume

```sh
docker volume create <volume>
```

## Visualizzare i volumi creati

```sh
docker volume ls
docker volume inspect <volume>
```

## Eliminazione volume

```sh
docker volume rm <volume>
```

## Rimozione di tutti i volumi non utilizzati

```sh
docker volume prune
```

## Associazione volume a container

```sh
docker run -it -v <volume>:<path_nel_container> <immagine> <servizio>
```

---

## **RETE**

## Creazione rete

```sh
docker network create <rete>
```

## Visualizzare le reti

```sh
docker network ls
docker network inspect <rete>
```

## Collegare container ad una rete

```sh
docker network connect <rete> <container>
```

## Rimozione rete

```sh
docker network rm <rete>
```

---

## **DOCKER COMPOSE**

## Avviare i servizi del file docker-compose.yml

```sh
docker compose up
```

**Opzioni:**

- `-d`: avvia in background
- `--build`: ricompila le immagini

## Fermare e rimuovere tutti i container definiti in docker-compose.yml

```sh
docker compose down
```

**Opzioni:**

- `--volumes`: rimuove i volumi associati

## Mostrare lo stato dei container gestiti da Compose

```sh
docker compose ps
```

## Visualizzare i log

```sh
docker compose logs
```

## Esempio di file `docker-compose.yml`

```yaml
version: '3'
services:
  web:
    image: nginx
    ports:
      - "8080:80"
  db:
    image: mysql
    environment:
      MYSQL_ROOT_PASSWORD: root
