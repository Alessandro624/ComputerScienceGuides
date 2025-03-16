# JUnit 5 - Guida Rapida

## Installazione
Per utilizzare JUnit 5, aggiungi le dipendenze appropriate al tuo progetto. Se stai utilizzando Maven, aggiungi le seguenti dipendenze al file `pom.xml`:

```xml
<dependencies>
    <!-- Dipendenza per JUnit Jupiter (per l'esecuzione dei test) -->
    <dependency>
        <groupId>org.junit.jupiter</groupId>
        <artifactId>junit-jupiter-api</artifactId>
        <version>5.7.0</version>
        <scope>test</scope>
    </dependency>
    
    <!-- Dipendenza per il motore di esecuzione dei test di JUnit Jupiter -->
    <dependency>
        <groupId>org.junit.jupiter</groupId>
        <artifactId>junit-jupiter-engine</artifactId>
        <version>5.7.0</version>
        <scope>test</scope>
    </dependency>
</dependencies>
```

Se stai usando Gradle, puoi aggiungere queste dipendenze al tuo file `build.gradle`:

```gradle
dependencies {
    testImplementation 'org.junit.jupiter:junit-jupiter-api:5.7.0'
    testRuntimeOnly 'org.junit.jupiter:junit-jupiter-engine:5.7.0'
}
```

## Struttura dei Test in JUnit 5
JUnit 5 è composto da tre sotto-progetti principali:
- **JUnit Jupiter**: il nuovo framework di programmazione e di esecuzione dei test.
- **JUnit Vintage**: supporto per l'esecuzione di test scritti con JUnit 3 e 4.
- **JUnit Platform**: una piattaforma comune per l'esecuzione di test.

### Esempio di un Test Base
Un test di base in JUnit 5 potrebbe apparire così:

```java
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class MyTest {

    @Test
    public void testSum() {
        int result = 1 + 1;
        assertEquals(2, result, "La somma deve essere 2");
    }
}
```

## Annotations

### @Test
L'annotazione `@Test` è usata per definire un metodo di test. Ogni metodo annotato con `@Test` viene eseguito come test.

```java
@Test
void test() {
    // Codice del test
}
```

### @BeforeEach e @AfterEach
- `@BeforeEach`: annotazione utilizzata per eseguire un metodo prima di ogni test.
- `@AfterEach`: annotazione utilizzata per eseguire un metodo dopo ogni test.

```java
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.AfterEach;

public class MyTest {

    @BeforeEach
    void setup() {
        // Codice eseguito prima di ogni test
    }

    @AfterEach
    void tearDown() {
        // Codice eseguito dopo ogni test
    }
}
```

### @BeforeAll e @AfterAll
- `@BeforeAll`: annotazione utilizzata per eseguire un metodo prima di tutti i test nella classe.
- `@AfterAll`: annotazione utilizzata per eseguire un metodo dopo tutti i test nella classe.

Questi metodi devono essere statici.

```java
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.AfterAll;

public class MyTest {

    @BeforeAll
    static void setupBeforeClass() {
        // Codice eseguito prima di tutti i test
    }

    @AfterAll
    static void tearDownAfterClass() {
        // Codice eseguito dopo tutti i test
    }
}
```

### @Disabled
L'annotazione `@Disabled` disabilita temporaneamente un test. Può essere utile se si desidera eseguire i test solo parzialmente.

```java
import org.junit.jupiter.api.Disabled;

@Disabled("Questo test è disabilitato per ora")
public void test() {
    // Codice del test disabilitato
}
```

### @TestInstance
L'annotazione `@TestInstance` specifica se il ciclo di vita della classe di test deve essere creato per ogni test o solo una volta per classe. Può essere utile per ottimizzare il tempo di esecuzione dei test.

```java
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.Test;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class MyTest {

    @Test
    void test1() {
        // Test 1
    }

    @Test
    void test2() {
        // Test 2
    }
}
```

## Asserzioni
JUnit 5 fornisce vari metodi di asserzione per verificare le condizioni durante i test:

### assertEquals
Verifica che due valori siano uguali.

```java
assertEquals(10, risultato);
```

### assertTrue / assertFalse
Verifica che una condizione sia vera o falsa.

```java
assertTrue(condizione);
assertFalse(condizione);
```

### assertNotNull / assertNull
Verifica che un valore non sia nullo o nullo.

```java
assertNotNull(obj);
assertNull(obj);
```

### assertThrows
Verifica che un'eccezione venga lanciata.

```java
assertThrows(IllegalArgumentException.class, () -> {
    throw new IllegalArgumentException("Messaggio di errore");
});
```

## Parametrizzazione dei Test
JUnit 5 permette di eseguire lo stesso test con diversi parametri utilizzando l'annotazione `@ParameterizedTest`.

### Esempio con `@ValueSource`
```java
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

public class MyTest {

    @ParameterizedTest
    @ValueSource(strings = {"apple", "banana", "orange"})
    void testWithStrings(String fruit) {
        assertNotNull(fruit);
    }
}
```

### Esempio con `@CsvSource`
```java
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

public class MyTest {

    @ParameterizedTest
    @CsvSource({"apple, 1", "banana, 2", "orange, 3"})
    void testWithCsv(String fruit, int number) {
        assertNotNull(fruit);
        assertTrue(number > 0);
    }
}
```

## Esecuzione dei Test
Per eseguire i test, puoi usare i seguenti comandi, a seconda del tuo strumento di build.

### Maven
```bash
mvn test
```

### Gradle
```bash
gradle test
```

## Test Suite
Un **Test Suite** è un gruppo di test che possono essere eseguiti insieme. Può essere creato usando l'annotazione `@Suite` in JUnit 5.

### Esempio:
```java
import org.junit.jupiter.api.Test;
import org.junit.platform.suite.api.SelectClasses;
import org.junit.platform.suite.api.Suite;

@Suite
@SelectClasses({MyTest.class, AnotherTest.class})
public class AllTests {
}
```

## Test di Timeout
Per eseguire un test con un limite di tempo, usa l'annotazione `@Timeout`.

### Esempio:
```java
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

public class MyTest {

    @Test
    @Timeout(5)
    void testWithTimeout() throws InterruptedException {
        Thread.sleep(1000);
    }
}
```

## Funzioni di Test Avanzate

### @EnabledIf / @DisabledIf
Le annotazioni `@EnabledIf` e `@DisabledIf` permettono di eseguire o disabilitare test in base a condizioni specifiche.

### Esempio:
```java
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;

public class MyTest {

    @Test
    @EnabledIf("com.example.MyCondition#isConditionTrue")
    void test() {
        // Test che viene eseguito solo se la condizione è vera
    }
}
```
