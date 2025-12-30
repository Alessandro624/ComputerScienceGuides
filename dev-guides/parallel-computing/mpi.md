# MPI - Guida Rapida

## Scopo

Questa guida fornisce un'introduzione a MPI (Message Passing Interface), lo standard per la programmazione parallela su sistemi distribuiti. Copre i concetti fondamentali, le funzioni principali e esempi pratici per lo sviluppo di applicazioni parallele.

## Prerequisiti

- Compilatore C/C++ (gcc/g++)
- Implementazione MPI (OpenMPI, MPICH)
- Conoscenza base di programmazione C/C++
- Familiarità con concetti di programmazione parallela

## Installazione

### Linux (Debian/Ubuntu)

```bash
sudo apt-get update
sudo apt-get install libopenmpi-dev openmpi-bin
```

### macOS

```bash
brew install open-mpi
```

### Verifica installazione

```bash
mpicc --version
mpirun --version
```

---

## Cos'è MPI?

**MPI (Message Passing Interface)** è uno standard di comunicazione per la programmazione parallela su sistemi distribuiti, in cui diversi processi (su nodi separati o sullo stesso nodo) scambiano dati attraverso messaggi. È utilizzato principalmente per applicazioni che richiedono alte prestazioni e devono eseguire calcoli paralleli su supercomputer o cluster.

MPI consente la comunicazione tra processi distribuiti attraverso la rete (o memoria condivisa) ed è fondamentale per la programmazione su sistemi multiprocessore e multi-core.

### Caratteristiche Principali

- **Semplicità**: MPI fornisce una vasta gamma di funzionalità, ma la sua complessità aumenta con la crescita dei sistemi.
- **Scalabilità**: È progettato per scalare da sistemi piccoli a supercomputer con migliaia di nodi.
- **Portabilità**: MPI è supportato da molte piattaforme, inclusi sistemi Linux, Windows e altre architetture hardware.
- **Sincronia**: MPI permette sia comunicazioni sincrone che asincrone.

## Concetti Fondamentali

### 1. Processo

Un "processo" è una singola istanza di un programma in esecuzione. MPI si basa sulla comunicazione tra questi processi.

### 2. Comunicazione

MPI offre vari tipi di comunicazione, tra cui:

- **Comunicazione punto-a-punto**: Trasferimento di messaggi tra due processi.
- **Comunicazione collettiva**: Comunicazione tra gruppi di processi, come broadcast, riduzioni, o raccolta.

### 3. MPI Communicator

Un **communicator** è un oggetto MPI che definisce il gruppo di processi coinvolti in una comunicazione. Il communicator predefinito è `MPI_COMM_WORLD`, che include tutti i processi.

## Comandi e Funzioni MPI Principali

### 1. Inizializzazione e Finalizzazione

Per iniziare una programmazione MPI, è necessario inizializzare MPI e terminare correttamente il programma:

```c
#include <mpi.h>

int main(int argc, char *argv[]) {
    MPI_Init(&argc, &argv);  // Inizializza MPI
    // Codice parallelo
    MPI_Finalize();  // Termina MPI
    return 0;
}
```

### 2. Ottenere il Rangolo di un Processo

Ogni processo in MPI ha un **rank** (ID univoco) che lo identifica nel comunicatore:

```c
int rank;
MPI_Comm_rank(MPI_COMM_WORLD, &rank);  // Ottieni il rank del processo
```

### 3. Numero di Processi

Per ottenere il numero totale di processi:

```c
int size;
MPI_Comm_size(MPI_COMM_WORLD, &size);  // Ottieni il numero totale di processi
```

### 4. Comunicazione Punto-a-Punto

#### MPI_Send

Per inviare un messaggio da un processo a un altro:

```c
int data = 100;
MPI_Send(&data, 1, MPI_INT, destination_rank, tag, MPI_COMM_WORLD);
```

- `data`: variabile da inviare.
- `1`: numero di elementi.
- `MPI_INT`: tipo di dato.
- `destination_rank`: il rank del processo di destinazione.
- `tag`: identificatore del messaggio.
- `MPI_COMM_WORLD`: il comunicatore.

#### MPI_Recv

Per ricevere un messaggio:

```c
int data;
MPI_Recv(&data, 1, MPI_INT, source_rank, tag, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
```

- `source_rank`: il rank del processo mittente.
- `MPI_STATUS_IGNORE`: ignorare lo stato del messaggio.

### 5. Comunicazione Collettiva

MPI fornisce diverse funzioni per la comunicazione tra gruppi di processi, come la raccolta di dati, riduzioni e broadcast.

#### MPI_Bcast (Broadcast)

Per inviare un dato da un processo a tutti gli altri:

```c
int data = 100;
MPI_Bcast(&data, 1, MPI_INT, 0, MPI_COMM_WORLD);
```

- Il processo con `rank = 0` invia `data` a tutti gli altri processi.

#### MPI_Reduce (Reduzione)

Per eseguire operazioni collettive come sommare valori da tutti i processi:

```c
int local_sum = 5, global_sum;
MPI_Reduce(&local_sum, &global_sum, 1, MPI_INT, MPI_SUM, 0, MPI_COMM_WORLD);
```

- Somma i valori di `local_sum` di tutti i processi e memorizza il risultato in `global_sum` nel processo con `rank = 0`.

### 6. Sincronizzazione

#### MPI_Barrier (Barriera di sincronizzazione)

Tutti i processi devono raggiungere questa barriera prima che la comunicazione prosegua:

```c
MPI_Barrier(MPI_COMM_WORLD);
```

### 7. Gestione degli Errori

MPI consente di gestire gli errori in modo che i programmi possano rispondere in modo appropriato a errori di comunicazione.

### 8. Profiler e Ottimizzazione

Gli strumenti di profiling come **mpiP** e **TAU** possono aiutare a monitorare le performance di un'applicazione MPI, individuando i colli di bottiglia e migliorando l'efficienza.

## Esempio di Programma MPI

Un esempio di programma MPI che somma numeri distribuiti tra più processi:

```c
#include <stdio.h>
#include <mpi.h>

int main(int argc, char *argv[]) {
    int rank, size, number, total_sum;

    MPI_Init(&argc, &argv);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    number = rank + 1;  // Ogni processo ha un numero da sommare
    printf("Processo %d ha il numero %d\n", rank, number);

    // Somma locale
    int local_sum = number;

    // Somma totale usando MPI_Reduce
    MPI_Reduce(&local_sum, &total_sum, 1, MPI_INT, MPI_SUM, 0, MPI_COMM_WORLD);

    // Il processo 0 stampa la somma totale
    if (rank == 0) {
        printf("La somma totale è: %d\n", total_sum);
    }

    MPI_Finalize();
    return 0;
}
```

### 9. Compilazione e Esecuzione

Per compilare e eseguire un programma MPI, utilizza `mpicc` (compilatore MPI) e `mpirun` (per eseguire il programma su più processi):

```bash
mpicc -o programma mpi_program.c
mpirun -np 4 ./programma
```

- `-np 4` indica che il programma deve essere eseguito su 4 processi.

---

## Best Practices

- **Minimizza comunicazioni**: Riduci il numero e la dimensione dei messaggi scambiati
- **Bilanciamento del carico**: Distribuisci equamente il lavoro tra i processi
- **Comunicazioni non bloccanti**: Usa `MPI_Isend`/`MPI_Irecv` per overlapping comunicazione/calcolo
- **Evita deadlock**: Fai attenzione all'ordine delle operazioni send/receive
- **Usa collettive**: Preferisci operazioni collettive (Broadcast, Reduce) a comunicazioni punto-punto multiple
- **Profiling**: Usa strumenti come Intel VTune o TAU per identificare bottleneck

## Riferimenti

- [Open MPI Documentation](https://www.open-mpi.org/doc/)
- [MPI Forum - Standard](https://www.mpi-forum.org/)
- [MPICH Documentation](https://www.mpich.org/documentation/)
- [MPI Tutorial](https://mpitutorial.com/)
