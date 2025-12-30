# Debugging Tools

## Scopo

Questa guida copre tool di debugging per analisi di binari, reverse engineering e exploit development in ambito security research.

## Prerequisiti

- Conoscenza assembly x86/x64
- Linguaggio C/C++
- Sistema Linux o Windows
- Comprensione architettura CPU

---

## GDB (GNU Debugger)

### Comandi Base

```bash
# Avvio
gdb ./binary
gdb -q ./binary  # Quiet mode
gdb -p PID  # Attach to process

# Running
(gdb) run
(gdb) run arg1 arg2
(gdb) run < input.txt

# Breakpoints
(gdb) break main
(gdb) break *0x08048456
(gdb) break function_name
(gdb) info breakpoints
(gdb) delete 1

# Execution
(gdb) continue
(gdb) step  # Step into
(gdb) next  # Step over
(gdb) finish  # Run until return
(gdb) until *0x08048460
```

### Inspection

```bash
# Registers
(gdb) info registers
(gdb) print $eax
(gdb) print/x $rsp

# Memory
(gdb) x/10x $esp  # 10 hex words
(gdb) x/s 0x08048500  # String
(gdb) x/20i $eip  # 20 instructions
(gdb) x/100xb 0x08048000  # 100 bytes hex

# Stack
(gdb) backtrace
(gdb) frame 0
(gdb) info frame

# Variables
(gdb) print variable
(gdb) print *pointer
(gdb) set variable = value
```

### GDB Extensions

#### GEF (GDB Enhanced Features)

```bash
# Installazione
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"

# Comandi
gef> checksec
gef> vmmap
gef> heap
gef> got
gef> pattern create 200
gef> pattern offset 0x41414141
gef> rop --search "pop rdi"
```

#### PEDA

```bash
# Installazione
git clone https://github.com/longld/peda.git ~/peda
echo "source ~/peda/peda.py" >> ~/.gdbinit

# Comandi
gdb-peda$ pdisass main
gdb-peda$ searchmem "/bin/sh"
gdb-peda$ ropgadget
gdb-peda$ checksec
```

#### pwndbg

```bash
# Installazione
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh

# Comandi
pwndbg> cyclic 200
pwndbg> cyclic -l 0x61616161
pwndbg> heap
pwndbg> bins
pwndbg> telescope $rsp 20
```

---

## WinDbg

### Setup

```
# Windows Debugging Tools (SDK)
# Preview da Microsoft Store

# Symbol path
.symfix
.reload
```

### Comandi

```
# Breakpoints
bp kernel32!CreateFileW
bl  # List
bc * # Clear all

# Execution
g  # Go
p  # Step over
t  # Step into

# Registers
r
r eax
r eax=0

# Memory
db address  # Bytes
dw address  # Words
dd address  # DWords
dq address  # QWords
da address  # ASCII
du address  # Unicode

# Disassembly
u address
uf function

# Stack
k  # Call stack
kp # With params
```

### Extensions

```
# Load
.load extension.dll

# WinDbg Preview modern commands
dx @$curprocess
dx @$cursession.Processes
```

---

## x64dbg

### Features

```
- GUI debugger Windows
- Plugin support
- Scripting
- Graph view

# Shortcuts
F2 - Breakpoint
F7 - Step into
F8 - Step over
F9 - Run
Ctrl+G - Go to address
```

### Scripting

```javascript
// JavaScript plugin
var entry = Memory.readPointer(ptr("0x400000"));
log(entry.toString(16));
```

---

## Radare2

### Analisi

```bash
# Open
r2 binary
r2 -d binary  # Debug mode
r2 -w binary  # Write mode

# Analisi
[0x00000000]> aaa  # Analyze all
[0x00000000]> afl  # List functions
[0x00000000]> s main  # Seek to main
[0x00000000]> pdf  # Print disassembly

# Visual mode
[0x00000000]> V
[0x00000000]> VV  # Graph mode
```

### Debug

```bash
[0x00000000]> db main  # Breakpoint
[0x00000000]> dc  # Continue
[0x00000000]> dr  # Registers
[0x00000000]> ds  # Step
[0x00000000]> px 100 @ rsp  # Print hex
```

### Cutter (GUI)

```bash
# Installazione
apt install cutter

# GUI per Radare2
```

---

## Ghidra

### Features

```
- NSA reverse engineering tool
- Decompiler
- Scripting (Java/Python)
- Collaborative

# Avvio
./ghidraRun
```

### Analysis

```
1. Create project
2. Import binary
3. Analyze (default options)
4. Navigate functions
5. View decompiler output
```

### Scripting

```python
# Ghidra Python script
from ghidra.app.decompiler import DecompInterface

decomp = DecompInterface()
decomp.openProgram(currentProgram)

func = getFunction("main")
results = decomp.decompileFunction(func, 60, monitor)
print(results.getDecompiledFunction().getC())
```

---

## IDA Pro/Free

### Navigation

```
- G: Go to address
- X: Cross-references
- N: Rename
- Y: Change type
- Space: Toggle graph/text
```

### Decompiler (Pro)

```
- F5: Decompile
- Tab: Switch views
```

### IDAPython

```python
# Script example
import ida_funcs
import idautils

for func_ea in idautils.Functions():
    func = ida_funcs.get_func(func_ea)
    print(f"Function at {hex(func.start_ea)}")
```

---

## Binary Ninja

```
- Modern RE platform
- Intermediate Language (BNIL)
- Python API
- Cloud collaboration
```

---

## Frida

### Hooking

```javascript
// JavaScript
Java.perform(function() {
    var MainActivity = Java.use("com.app.MainActivity");
    MainActivity.secretFunction.implementation = function() {
        console.log("Called!");
        return this.secretFunction();
    };
});
```

```bash
# CLI
frida -U -f com.app.name -l script.js
frida-ps -U
frida-trace -U -f com.app.name -i "open*"
```

### Python Binding

```python
import frida

device = frida.get_usb_device()
session = device.attach("target")
script = session.create_script("""
    Interceptor.attach(ptr("0x12345"), {
        onEnter: function(args) {
            console.log("Called");
        }
    });
""")
script.load()
```

---

## Pwntools

```python
from pwn import *

# Connection
p = process("./binary")
p = remote("host", port)

# ELF
elf = ELF("./binary")
print(hex(elf.symbols["main"]))
print(hex(elf.got["puts"]))

# Payload
payload = b"A" * 64
payload += p64(0xdeadbeef)

# ROP
rop = ROP(elf)
rop.puts(elf.got["puts"])
rop.main()
print(rop.dump())

# Send/Receive
p.sendline(payload)
leak = p.recvline()
```

---

## Memory Tools

### Valgrind

```bash
# Memory errors
valgrind ./binary

# Leak check
valgrind --leak-check=full ./binary

# Detailed
valgrind --leak-check=full --show-leak-kinds=all ./binary
```

### AddressSanitizer

```bash
# Compile
gcc -fsanitize=address -g -o binary source.c

# Run
./binary
# Reports memory errors with stack traces
```

---

## Best Practices

- **Snapshots**: Usa VM snapshots
- **Isolation**: Ambiente isolato
- **Notes**: Documenta findings
- **Scripts**: Automatizza ripetitivo
- **Updates**: Tool aggiornati

## Riferimenti

- [GDB Documentation](https://www.gnu.org/software/gdb/documentation/)
- [GEF](https://gef.readthedocs.io/)
- [Radare2](https://rada.re/)
- [Ghidra](https://ghidra-sre.org/)
