# Reverse Engineering Mobile

## Scopo

Questa guida copre tecniche di reverse engineering per applicazioni mobile Android e iOS, utilizzate durante penetration test e security assessment.

## Prerequisiti

- Android Studio / Xcode
- Dispositivo rooted/jailbroken o emulatore
- apktool, jadx, frida
- **Autorizzazione per testing**

## Installazione

```bash
# Android tools
sudo apt-get install apktool jadx dex2jar

# Frida
pip install frida-tools

# iOS tools (macOS)
brew install class-dump
```

---

## Android Reverse Engineering

### Ottenere APK

```bash
# Da device
adb shell pm list packages | grep target
adb shell pm path com.target.app
adb pull /data/app/com.target.app/base.apk

# Da Play Store
# apkpure.com, apkmirror.com
```

### Decompilare APK

```bash
# apktool (risorse + smali)
apktool d app.apk -o output/

# jadx (Java source)
jadx app.apk -d output/
jadx-gui app.apk  # GUI

# dex2jar + jd-gui
d2j-dex2jar app.apk
jd-gui classes-dex2jar.jar
```

### Struttura APK

```
AndroidManifest.xml  - Permessi, componenti
classes.dex          - Bytecode Dalvik
resources.arsc       - Risorse compilate
res/                 - Layout, immagini
assets/              - File raw
lib/                 - Librerie native (.so)
META-INF/            - Firma
```

### Analisi Manifest

```bash
# Estrarre manifest leggibile
apktool d app.apk
cat output/AndroidManifest.xml

# Cercare
- exported components
- debuggable="true"
- allowBackup="true"
- custom permissions
```

### Analisi Codice

```bash
# Cerca hardcoded secrets
grep -rn "api_key\|secret\|password\|token" output/

# Cerca URL/endpoint
grep -rn "http://\|https://" output/

# Cerca crypto
grep -rn "AES\|RSA\|MD5\|SHA" output/
```

---

## iOS Reverse Engineering

### Ottenere IPA

```bash
# Da device jailbroken
# Clutch, frida-ios-dump

# Frida dump
frida-ios-dump -u -H 192.168.1.X -l
frida-ios-dump -u -H 192.168.1.X com.target.app
```

### Decriptare IPA

```bash
# iOS app da App Store sono criptate
# Usa frida-ios-dump su device jailbroken

# Verifica encryption
otool -l app | grep -A4 LC_ENCRYPTION_INFO
```

### Struttura IPA

```
Payload/
  App.app/
    Info.plist       - Configurazione
    App (binary)     - Mach-O executable
    Frameworks/      - Librerie
    _CodeSignature/  - Firma
```

### Analisi Binary

```bash
# class-dump (Objective-C)
class-dump App > headers.h

# otool
otool -L App  # Librerie linkate
otool -ov App # Objective-C info

# strings
strings App | grep -i "http\|api\|key"

# Hopper Disassembler (GUI)
# IDA Pro
# Ghidra
```

---

## Frida Dynamic Analysis

### Setup

```bash
# Installa server su device
# Download da github.com/frida/frida/releases
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"
```

### Comandi Base

```bash
# Lista processi
frida-ps -U

# Attach
frida -U com.target.app

# Run script
frida -U -l script.js com.target.app
```

### Script Esempio

```javascript
// Hook method
Java.perform(function() {
    var MainActivity = Java.use("com.target.app.MainActivity");
    
    MainActivity.checkPassword.implementation = function(password) {
        console.log("Password entered: " + password);
        var result = this.checkPassword(password);
        console.log("Result: " + result);
        return result;
    };
});
```

### Bypass SSL Pinning

```javascript
// Android
Java.perform(function() {
    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TrustManagerImpl.checkServerTrusted.implementation = function() {
        console.log('SSL Pinning Bypassed');
        return;
    };
});
```

### Objection (Frida wrapper)

```bash
pip install objection

# Explore app
objection -g com.target.app explore

# Commands
objection> android sslpinning disable
objection> android root disable
objection> android hooking list classes
objection> android hooking watch class com.target.Class
```

---

## Native Code Analysis

### Android (.so)

```bash
# Estrai librerie
unzip app.apk lib/*

# Analisi
objdump -d libnative.so
readelf -s libnative.so

# Ghidra per analisi avanzata
```

### iOS (Frameworks)

```bash
# Estrai frameworks
# Analizza con Hopper/IDA/Ghidra
```

---

## Analisi Traffico

### Setup Proxy

```bash
# Burp Suite/mitmproxy

# Android
# Installa CA cert in user certs (Android 7+)
# O usa Frida per bypass pinning

# iOS
# Installa profilo con CA
# Bypass pinning se necessario
```

### Wireshark

```bash
# Per traffico non-HTTP
# Cattura su interfaccia device/emulatore
```

---

## Emulatori

### Android

```bash
# Android Studio AVD
# Genymotion
# Nox (x86)

# Root emulator
adb root
```

### iOS

```bash
# Xcode Simulator (limitato)
# Corellium (cloud, full jailbreak)
```

---

## Tools Utili

| Tool | Platform | Uso |
|------|----------|-----|
| jadx | Android | Decompiler Java |
| apktool | Android | Disassembly/rebuild |
| Frida | Both | Dynamic instrumentation |
| Objection | Both | Frida automation |
| Hopper | iOS/macOS | Disassembler |
| Ghidra | Both | Reverse engineering |
| MobSF | Both | Automated analysis |
| Drozer | Android | Security assessment framework |
| Needle | iOS | iOS security testing (deprecated) |
| ApkX | Android | Decompiler wrapper |
| APK Studio | Android | IDE per reverse engineering |
| Postman | Both | API testing |
| Burp Suite | Both | Proxy e web security |
| Ettercap | Both | Network analysis |

---

## MobSF (Automated)

```bash
docker pull opensecurity/mobile-security-framework-mobsf
docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf

# Upload APK/IPA via web interface
# http://localhost:8000
```

---

## Best Practices

- **Legal**: Solo su app autorizzate
- **Static first**: Analizza prima staticamente
- **Document**: Log tutti i finding
- **Responsible**: Segnala vulnerabilità
- **Lab environment**: Device dedicato per test

## Riferimenti

- [OWASP Mobile Testing Guide](https://owasp.org/www-project-mobile-security-testing-guide/)
- [Frida Documentation](https://frida.re/docs/home/)
- [jadx](https://github.com/skylot/jadx)
- [MobSF](https://mobsf.github.io/docs/)
