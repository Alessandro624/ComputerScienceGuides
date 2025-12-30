# CMake

## Scopo

Questa guida fornisce una panoramica di CMake, un sistema di build cross-platform per la compilazione di progetti C/C++.

## Prerequisiti

- CMake installato (versione 3.x consigliata)
- Compilatore C/C++ (GCC, Clang, MSVC)
- Conoscenza base di C/C++

## Installazione

### Linux (Debian/Ubuntu)

```bash
sudo apt-get update
sudo apt-get install cmake
```

### Windows

Scarica l'installer da [cmake.org](https://cmake.org/download/) o usa:

```powershell
winget install Kitware.CMake
```

### macOS

```bash
brew install cmake
```

---

## Struttura Progetto Base

```
project/
├── CMakeLists.txt
├── src/
│   └── main.cpp
├── include/
│   └── header.h
└── build/
```

---

## CMakeLists.txt Minimo

```cmake
cmake_minimum_required(VERSION 3.10)

# Nome del progetto
project(MyProject VERSION 1.0)

# Standard C++
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Eseguibile
add_executable(myapp src/main.cpp)
```

---

## Comandi Base

### Configurazione

```bash
# Crea directory build
mkdir build && cd build

# Configura progetto
cmake ..

# Con generator specifico
cmake -G "Unix Makefiles" ..
cmake -G "Ninja" ..
cmake -G "Visual Studio 17 2022" ..
```

### Build

```bash
# Build standard
cmake --build .

# Con parallelismo
cmake --build . -j 4

# Configurazione specifica
cmake --build . --config Release
cmake --build . --config Debug
```

### Installazione

```bash
cmake --install . --prefix /usr/local
```

---

## Variabili Comuni

```cmake
# Percorsi
set(CMAKE_SOURCE_DIR)     # Root sorgente
set(CMAKE_BINARY_DIR)     # Directory build
set(CMAKE_CURRENT_SOURCE_DIR)  # CMakeLists corrente

# Configurazioni
set(CMAKE_BUILD_TYPE Release)  # Debug, Release, RelWithDebInfo
set(CMAKE_INSTALL_PREFIX "/usr/local")

# Compilatore
set(CMAKE_C_COMPILER gcc)
set(CMAKE_CXX_COMPILER g++)

# Flag
set(CMAKE_CXX_FLAGS "-Wall -Wextra")
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")
```

---

## Librerie

### Libreria Statica

```cmake
add_library(mylib STATIC
    src/lib1.cpp
    src/lib2.cpp
)

target_include_directories(mylib PUBLIC include/)
```

### Libreria Condivisa

```cmake
add_library(mylib SHARED
    src/lib1.cpp
)
```

### Collegamento Librerie

```cmake
target_link_libraries(myapp PRIVATE mylib)
target_link_libraries(myapp PRIVATE pthread)
```

---

## Find Package

```cmake
# Trova libreria esterna
find_package(OpenSSL REQUIRED)
find_package(Boost 1.70 REQUIRED COMPONENTS filesystem)

# Usa
target_link_libraries(myapp PRIVATE OpenSSL::SSL)
target_link_libraries(myapp PRIVATE Boost::filesystem)
```

---

## Sottoprogetti

```cmake
# Aggiungi sottodirectory
add_subdirectory(libs/mylib)

# Usa target da sottoprogetto
target_link_libraries(myapp PRIVATE mylib)
```

---

## Opzioni e Configurazioni

```cmake
# Definisci opzione
option(ENABLE_TESTS "Enable testing" ON)

# Condizionale
if(ENABLE_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Configurazione per OS
if(WIN32)
    # Windows specific
elseif(UNIX)
    # Unix/Linux specific
endif()
```

---

## Testing con CTest

```cmake
enable_testing()

add_executable(test_main tests/test_main.cpp)
target_link_libraries(test_main PRIVATE mylib)

add_test(NAME MainTest COMMAND test_main)
```

```bash
# Esegui test
ctest
ctest -V  # Verbose
ctest -R "pattern"  # Filtra test
```

---

## Esempio Completo

```cmake
cmake_minimum_required(VERSION 3.15)

project(Example
    VERSION 1.0.0
    DESCRIPTION "Example project"
    LANGUAGES CXX
)

# Options
option(BUILD_TESTS "Build tests" ON)
option(BUILD_DOCS "Build documentation" OFF)

# Standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Warnings
if(MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Library
add_library(mylib
    src/module1.cpp
    src/module2.cpp
)

target_include_directories(mylib
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

# Executable
add_executable(myapp src/main.cpp)
target_link_libraries(myapp PRIVATE mylib)

# Tests
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Install
install(TARGETS mylib myapp
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

install(DIRECTORY include/ DESTINATION include)
```

---

## Best Practices

- **Modern CMake**: Usa `target_*` invece di variabili globali
- **Out-of-source**: Compila sempre in directory separata
- **Versionamento**: Specifica versione minima CMake
- **Targets**: Preferisci target a variabili
- **PRIVATE/PUBLIC**: Gestisci correttamente la visibilita

## Riferimenti

- [CMake Documentation](https://cmake.org/documentation/)
- [Modern CMake](https://cliutils.gitlab.io/modern-cmake/)
- [CMake Tutorial](https://cmake.org/cmake/help/latest/guide/tutorial/)
