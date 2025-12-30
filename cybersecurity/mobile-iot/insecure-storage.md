# Insecure Storage Mobile

## Scopo

Questa guida copre le vulnerabilità di insecure data storage nelle applicazioni mobile Android e iOS, con tecniche di identificazione e exploitation.

## Prerequisiti

- Dispositivo rooted (Android) o jailbroken (iOS)
- adb, Frida
- Conoscenza filesystem mobile
- **Autorizzazione per testing**

---

## Concetto

```
Le app spesso memorizzano dati sensibili in modo insicuro:
- File in chiaro
- Database non criptati
- SharedPreferences/NSUserDefaults
- Logs
- Cache
- Keychain configurato male
```

---

## Android Storage Locations

### Internal Storage

```bash
# Accessibile solo all'app (senza root)
/data/data/com.app.package/

# Struttura
├── shared_prefs/    # SharedPreferences (XML)
├── databases/       # SQLite databases
├── files/           # App files
├── cache/           # Cache
└── lib/             # Native libraries
```

### External Storage

```bash
# Accessibile a tutti (pre-Android 11)
/sdcard/Android/data/com.app.package/
/storage/emulated/0/

# Spesso contiene:
# - Downloads
# - Log files
# - Backup
```

---

## Android Analysis

### Accesso con ADB

```bash
# Richiede root o debuggable app
adb root
adb shell

# Naviga app directory
cd /data/data/com.target.app/
ls -la
```

### SharedPreferences

```bash
# File XML
cat /data/data/com.app/shared_prefs/*.xml

# Cerca secrets
grep -r "token\|password\|api_key\|secret" shared_prefs/
```

### Database SQLite

```bash
# Copia database
adb pull /data/data/com.app/databases/app.db

# Analisi
sqlite3 app.db
.tables
.schema users
SELECT * FROM users;
```

### File Analysis

```bash
# Cerca file sensibili
find /data/data/com.app/ -name "*.json" -o -name "*.xml" -o -name "*.txt"

# Strings su file binari
strings /data/data/com.app/files/config.bin
```

---

## iOS Storage Locations

### Application Sandbox

```bash
# Ogni app isolata in sandbox
/var/mobile/Containers/

# Bundle (read-only)
/var/mobile/Containers/Bundle/Application/UUID/

# Data (read-write)
/var/mobile/Containers/Data/Application/UUID/
├── Documents/       # Persistent data
├── Library/
│   ├── Caches/      # Cache
│   ├── Preferences/ # plist files
│   └── Cookies/     # Cookies
└── tmp/             # Temporary
```

### Trova App Directory

```bash
# Su device jailbroken
find /var/mobile/Containers/Data/Application -name "*.app" 2>/dev/null

# O cerca per nome
grep -r "com.target.app" /var/mobile/Containers/
```

---

## iOS Analysis

### Property Lists

```bash
# Preferenze utente
cat /var/mobile/Containers/Data/Application/UUID/Library/Preferences/com.app.plist

# Converti binario plist
plutil -p file.plist
```

### SQLite Databases

```bash
# Core Data, realm, sqlite
find . -name "*.sqlite" -o -name "*.db" -o -name "*.realm"

sqlite3 database.sqlite
.tables
SELECT * FROM ZTABLE;
```

### Keychain

```bash
# Keychain dump (richiede jailbreak)
# Tools: keychain-dumper, Keychain-Dumper

./keychain-dumper

# O con Frida
objection -g com.app explore
> ios keychain dump
```

---

## Frida per Storage Analysis

### Android

```javascript
// Hook file operations
Java.perform(function() {
    var File = Java.use('java.io.File');
    File.write.overload('java.lang.String').implementation = function(data) {
        console.log('Writing: ' + data);
        return this.write(data);
    };
});
```

### iOS

```javascript
// Hook NSUserDefaults
var NSUserDefaults = ObjC.classes.NSUserDefaults;

Interceptor.attach(NSUserDefaults['- setObject:forKey:'].implementation, {
    onEnter: function(args) {
        console.log('Key: ' + ObjC.Object(args[3]));
        console.log('Value: ' + ObjC.Object(args[2]));
    }
});
```

### Objection

```bash
# Android
objection -g com.app explore
> android hooking search classes SharedPreferences
> android hooking watch class android.content.SharedPreferences

# iOS
objection -g com.app explore
> ios nsuserdefaults get
> ios keychain dump
```

---

## Vulnerabilità Comuni

### Credentials in Chiaro

```bash
# Password in SharedPreferences
<string name="password">SuperSecret123</string>

# Token in NSUserDefaults
{"access_token": "eyJhbGciOiJIUzI1NiIs..."}
```

### Database Non Criptato

```bash
# SQLite con dati sensibili
SELECT username, password, credit_card FROM users;
```

### Backup Insicuro

```bash
# Android - allowBackup="true"
adb backup -f backup.ab com.app
# Contiene tutti i dati app

# iOS - backup iTunes/iCloud
# Può contenere dati sensibili
```

### Logs

```bash
# Android logcat
adb logcat | grep -i "password\|token\|key"

# iOS syslog (jailbroken)
socat - UNIX-CONNECT:/var/run/lockdown/syslog.sock
```

---

## Testing Checklist

```
□ SharedPreferences/NSUserDefaults
□ SQLite databases
□ Realm databases
□ Core Data
□ Cache files
□ Log files
□ Keychain (iOS)
□ Backup data
□ External storage (Android)
□ WebView cache
□ Cookie storage
□ Clipboard
```

---

## Mitigazioni

### Android

```java
// EncryptedSharedPreferences
MasterKey masterKey = new MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build();

SharedPreferences sharedPreferences = EncryptedSharedPreferences.create(
    context, "secret_prefs", masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
);

// SQLCipher per database
```

### iOS

```swift
// Keychain con accessibilità corretta
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    kSecAttrAccount as String: account,
    kSecValueData as String: data
]
```

### Generale

```
- Non memorizzare secrets non necessari
- Encryption at rest
- Secure delete
- Disable backup per dati sensibili
```

---

## Best Practices

- **Root/Jailbreak**: Necessario per analisi completa
- **Backup analysis**: Includi sempre
- **Runtime**: Combina analisi statica e dinamica
- **Document**: Screenshot e export di tutti i finding
- **Remediation**: Suggerisci fix specifici

## Riferimenti

- [OWASP Mobile Top 10 - M2](https://owasp.org/www-project-mobile-top-10/)
- [MSTG Data Storage](https://mobile-security.gitbook.io/mobile-security-testing-guide/android-testing-guide/0x05d-testing-data-storage)
- [SQLCipher](https://www.zetetic.net/sqlcipher/)
- [Android EncryptedSharedPreferences](https://developer.android.com/reference/androidx/security/crypto/EncryptedSharedPreferences)
