# Gradle

## Scopo

Questa guida fornisce una panoramica di Gradle, il build tool moderno per progetti Java, Kotlin, Android e multi-linguaggio.

## Prerequisiti

- Java JDK 8+
- Terminale

---

## Installazione

```bash
# SDKMAN (consigliato)
sdk install gradle

# Homebrew (macOS)
brew install gradle

# Windows Scoop
scoop install gradle

# Verifica
gradle --version
```

---

## Gradle Wrapper

Il wrapper garantisce una versione Gradle consistente.

```bash
# Genera wrapper
gradle wrapper

# Aggiorna versione
./gradlew wrapper --gradle-version 8.5

# Usa wrapper (consigliato)
./gradlew build  # Linux/macOS
gradlew.bat build  # Windows
```

### File Wrapper

```
project/
├── gradle/
│   └── wrapper/
│       ├── gradle-wrapper.jar
│       └── gradle-wrapper.properties
├── gradlew
└── gradlew.bat
```

---

## Struttura Progetto

```
project/
├── build.gradle(.kts)
├── settings.gradle(.kts)
├── gradle.properties
├── src/
│   ├── main/
│   │   ├── java/
│   │   └── resources/
│   └── test/
│       ├── java/
│       └── resources/
└── build/
```

---

## build.gradle (Groovy)

```groovy
plugins {
    id 'java'
    id 'application'
}

group = 'com.example'
version = '1.0.0'

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

repositories {
    mavenCentral()
    maven { url 'https://jitpack.io' }
}

dependencies {
    implementation 'org.springframework.boot:spring-boot-starter:3.2.0'
    implementation 'com.google.guava:guava:32.1.3-jre'
    
    compileOnly 'org.projectlombok:lombok:1.18.30'
    annotationProcessor 'org.projectlombok:lombok:1.18.30'
    
    testImplementation 'org.junit.jupiter:junit-jupiter:5.10.1'
    testRuntimeOnly 'org.junit.platform:junit-platform-launcher'
}

application {
    mainClass = 'com.example.Main'
}

test {
    useJUnitPlatform()
}

jar {
    manifest {
        attributes 'Main-Class': 'com.example.Main'
    }
}
```

---

## build.gradle.kts (Kotlin DSL)

```kotlin
plugins {
    java
    application
    id("org.springframework.boot") version "3.2.0"
}

group = "com.example"
version = "1.0.0"

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.springframework.boot:spring-boot-starter")
    implementation("com.google.guava:guava:32.1.3-jre")
    
    compileOnly("org.projectlombok:lombok:1.18.30")
    annotationProcessor("org.projectlombok:lombok:1.18.30")
    
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.1")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

application {
    mainClass.set("com.example.Main")
}

tasks.test {
    useJUnitPlatform()
}
```

---

## settings.gradle

```groovy
rootProject.name = 'my-project'

// Multi-module
include 'app'
include 'library'
include 'common'

// Da altra directory
include 'subprojects:moduleA'
project(':subprojects:moduleA').projectDir = file('modules/moduleA')
```

---

## Comandi Base

```bash
# Build
./gradlew build

# Clean
./gradlew clean

# Clean + Build
./gradlew clean build

# Compile
./gradlew compileJava

# Test
./gradlew test

# Run applicazione
./gradlew run

# Lista task
./gradlew tasks
./gradlew tasks --all

# Dipendenze
./gradlew dependencies
./gradlew dependencies --configuration implementation

# Help task
./gradlew help --task build

# Build senza test
./gradlew build -x test

# Parallel
./gradlew build --parallel

# Continuous build
./gradlew build --continuous

# Debug
./gradlew build --info
./gradlew build --debug
./gradlew build --stacktrace
```

---

## Dependency Configurations

| Configuration | Descrizione |
|---------------|-------------|
| `implementation` | Compile + runtime, non esposta |
| `api` | Compile + runtime, esposta |
| `compileOnly` | Solo compile time |
| `runtimeOnly` | Solo runtime |
| `testImplementation` | Test compile + runtime |
| `annotationProcessor` | Annotation processing |

```groovy
dependencies {
    // Dipendenza modulo
    implementation(project(':common'))
    
    // File locale
    implementation(files('libs/custom.jar'))
    
    // Directory
    implementation(fileTree(dir: 'libs', include: ['*.jar']))
    
    // Esclusioni
    implementation('org.example:lib:1.0') {
        exclude group: 'org.unwanted'
        exclude module: 'unwanted-module'
    }
    
    // Force version
    implementation('com.google.guava:guava') {
        version {
            strictly '32.1.3-jre'
        }
    }
}
```

---

## Task Personalizzati

```groovy
// Task semplice
tasks.register('hello') {
    doLast {
        println 'Hello, World!'
    }
}

// Task con configurazione
tasks.register('greet') {
    group = 'custom'
    description = 'Prints a greeting'
    
    doFirst {
        println 'Starting...'
    }
    
    doLast {
        println 'Hello!'
    }
}

// Task con dipendenze
tasks.register('fullBuild') {
    dependsOn 'clean', 'build', 'test'
    
    doLast {
        println 'Full build completed!'
    }
}

// Copy task
tasks.register('copyDocs', Copy) {
    from 'src/docs'
    into 'build/docs'
    include '**/*.md'
}

// Exec task
tasks.register('runScript', Exec) {
    workingDir 'scripts'
    commandLine 'bash', 'deploy.sh'
}
```

---

## Multi-Project Build

### settings.gradle

```groovy
rootProject.name = 'parent'
include 'app', 'core', 'api'
```

### Root build.gradle

```groovy
// Configurazione comune a tutti
allprojects {
    repositories {
        mavenCentral()
    }
}

// Solo subprojects
subprojects {
    apply plugin: 'java'
    
    java {
        sourceCompatibility = JavaVersion.VERSION_17
    }
    
    dependencies {
        testImplementation 'org.junit.jupiter:junit-jupiter:5.10.1'
    }
    
    test {
        useJUnitPlatform()
    }
}
```

### Subproject build.gradle

```groovy
// app/build.gradle
plugins {
    id 'application'
}

dependencies {
    implementation project(':core')
    implementation project(':api')
}

application {
    mainClass = 'com.example.App'
}
```

---

## gradle.properties

```properties
# JVM settings
org.gradle.jvmargs=-Xmx2048m -XX:+HeapDumpOnOutOfMemoryError

# Parallel
org.gradle.parallel=true

# Caching
org.gradle.caching=true

# Daemon
org.gradle.daemon=true

# Console
org.gradle.console=rich

# Custom properties
myProperty=value
```

---

## Plugin Comuni

```groovy
plugins {
    // Java
    id 'java'
    id 'java-library'
    id 'application'
    
    // Spring Boot
    id 'org.springframework.boot' version '3.2.0'
    id 'io.spring.dependency-management' version '1.1.4'
    
    // Kotlin
    id 'org.jetbrains.kotlin.jvm' version '1.9.21'
    
    // Shadow (fat JAR)
    id 'com.github.johnrengelman.shadow' version '8.1.1'
    
    // Publishing
    id 'maven-publish'
}
```

---

## Pubblicazione

```groovy
plugins {
    id 'maven-publish'
}

publishing {
    publications {
        maven(MavenPublication) {
            from components.java
            
            pom {
                name = 'My Library'
                description = 'A library'
                url = 'https://example.com'
            }
        }
    }
    
    repositories {
        maven {
            url = uri("https://maven.example.com/releases")
            credentials {
                username = project.findProperty("mavenUser")
                password = project.findProperty("mavenPassword")
            }
        }
    }
}
```

---

## Best Practices

- **Wrapper**: Sempre usa e commit il wrapper
- **Kotlin DSL**: Preferisci per type-safety
- **Version Catalog**: Centralizza versioni
- **Configuration Cache**: Abilita per velocita
- **Build Scans**: Usa per debugging

## Riferimenti

- [Gradle Documentation](https://docs.gradle.org/)
- [Gradle Plugin Portal](https://plugins.gradle.org/)
- [Gradle Kotlin DSL](https://docs.gradle.org/current/userguide/kotlin_dsl.html)
