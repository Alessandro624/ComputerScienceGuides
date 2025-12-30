# Certificate Pinning Bypass

## Scopo

Questa guida copre tecniche per bypassare certificate pinning in applicazioni mobile, necessarie per intercettare traffico HTTPS durante penetration test.

## Prerequisiti

- Burp Suite o mitmproxy
- Frida con objection
- Dispositivo rooted/jailbroken
- **Autorizzazione per testing**

## Installazione

```bash
# Frida
pip install frida-tools objection

# Android - Frida server
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
```

---

## Concetto

```
Certificate Pinning = app verifica che certificato server
corrisponda a quello "pinnato" nell'app

Tipi:
- Public key pinning
- Certificate pinning
- Hash pinning (SPKI)

Senza bypass = impossibile intercettare traffico
```

---

## Setup Proxy

### Burp Suite

```bash
# Genera CA cert
Proxy → Options → Import/Export CA Certificate

# Android - installa certificato
adb push cacert.der /sdcard/
# Settings → Security → Install from storage

# iOS
# Safari → http://burp:8080 → Download CA
# Settings → Profile Downloaded → Install
```

### Android System CA (Android 7+)

```bash
# Android 7+ non trusts user CA per default
# Opzioni:
1. Network Security Config
2. Root + magisk module
3. Frida/objection
```

---

## Frida Universal Bypass

### Android

```javascript
// ssl_pinning_bypass.js
Java.perform(function() {
    console.log("[*] SSL Pinning Bypass");
    
    // TrustManagerImpl
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function() {
            console.log("[+] TrustManagerImpl bypassed");
            return arguments[0];
        };
    } catch(e) {}
    
    // OkHttp3
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {
            console.log("[+] OkHttp3 CertificatePinner bypassed");
            return;
        };
    } catch(e) {}
    
    // TrustManager
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var TrustManager = Java.registerClass({
            name: 'com.custom.TrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function() {},
                checkServerTrusted: function() {},
                getAcceptedIssuers: function() { return []; }
            }
        });
    } catch(e) {}
});
```

### Esecuzione

```bash
frida -U -l ssl_pinning_bypass.js -f com.target.app --no-pause
```

---

## Objection (Automatic)

### Android

```bash
# Start app con objection
objection -g com.target.app explore

# Bypass SSL pinning
com.target.app on (Android: 10) [usb] # android sslpinning disable

# Output:
# - Attempting to disable SSL Pinning...
# - OkHTTP3 CertificatePinner disabled
# - TrustManagerImpl disabled
# - ...
```

### iOS

```bash
objection -g com.target.app explore

# Bypass pinning
com.target.app on (iPhone: 14.0) [usb] # ios sslpinning disable
```

---

## Bypass Specifici

### OkHttp3

```javascript
Java.perform(function() {
    var CertificatePinner = Java.use('okhttp3.CertificatePinner');
    
    CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
        console.log('[+] OkHttp check() bypassed for: ' + hostname);
    };
    
    CertificatePinner.check$okhttp.overload('java.lang.String', 'kotlin.jvm.functions.Function0').implementation = function(hostname, peerCertificates) {
        console.log('[+] OkHttp check$okhttp() bypassed for: ' + hostname);
    };
});
```

### Retrofit/OkHttp Builder

```javascript
Java.perform(function() {
    var Builder = Java.use('okhttp3.OkHttpClient$Builder');
    
    Builder.certificatePinner.implementation = function(certificatePinner) {
        console.log('[+] OkHttpClient.Builder.certificatePinner() bypassed');
        return this;
    };
});
```

### Volley

```javascript
Java.perform(function() {
    var HurlStack = Java.use('com.android.volley.toolbox.HurlStack');
    
    HurlStack.createConnection.implementation = function(url) {
        var connection = this.createConnection(url);
        if (url.getProtocol() === 'https') {
            connection.setSSLSocketFactory(/* custom factory */);
        }
        return connection;
    };
});
```

### TrustKit (iOS)

```javascript
if (ObjC.available) {
    var TrustKit = ObjC.classes.TrustKit;
    if (TrustKit) {
        Interceptor.replace(TrustKit['+ initSharedInstanceWithConfiguration:'].implementation, new NativeCallback(function() {
            console.log('[+] TrustKit initSharedInstanceWithConfiguration bypassed');
        }, 'void', []));
    }
}
```

### AFNetworking (iOS)

```javascript
var AFSecurityPolicy = ObjC.classes.AFSecurityPolicy;

Interceptor.attach(AFSecurityPolicy['- setSSLPinningMode:'].implementation, {
    onEnter: function(args) {
        args[2] = ptr(0); // AFSSLPinningModeNone
        console.log('[+] AFSecurityPolicy pinning mode set to None');
    }
});

Interceptor.attach(AFSecurityPolicy['- setAllowInvalidCertificates:'].implementation, {
    onEnter: function(args) {
        args[2] = ptr(1); // true
        console.log('[+] AFSecurityPolicy allow invalid certs');
    }
});
```

---

## Patching APK

### Modifica Network Security Config

```bash
# Decompile
apktool d app.apk -o output/

# Crea/modifica network_security_config.xml
cat > output/res/xml/network_security_config.xml << EOF
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config>
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
</network-security-config>
EOF

# Aggiungi riferimento in AndroidManifest.xml
# android:networkSecurityConfig="@xml/network_security_config"

# Rebuild
apktool b output -o patched.apk

# Sign
jarsigner -keystore keystore.jks patched.apk alias
# o
apksigner sign --ks keystore.jks patched.apk
```

---

## Root Detection Bypass

### Spesso combinato con pinning

```javascript
// Frida - bypass root detection
Java.perform(function() {
    // Build.TAGS
    var Build = Java.use('android.os.Build');
    Build.TAGS.value = 'release-keys';
    
    // File.exists per su
    var File = Java.use('java.io.File');
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        if (path.indexOf('su') !== -1 || path.indexOf('magisk') !== -1) {
            return false;
        }
        return this.exists();
    };
});
```

### Objection

```bash
# Android
objection -g com.app explore
> android root disable

# iOS
objection -g com.app explore
> ios jailbreak disable
```

---

## Tools Alternativi

### apk-mitm

```bash
# Patching automatico APK
npx apk-mitm app.apk

# Output: app-patched.apk con pinning disabilitato
```

### SSL Kill Switch 2 (iOS)

```bash
# Cydia package per jailbroken device
# Disabilita SSL pinning system-wide
```

---

## Troubleshooting

```
Problema: App ancora non va attraverso proxy

Soluzioni:
1. Verifica che Frida server sia running
2. Prova bypass script multipli
3. Analizza codice per custom implementation
4. Verifica non-standard ports
5. Controlla native code pinning
```

---

## Best Practices

- **Script multiple**: Alcune app hanno multiple implementazioni
- **Versioning**: Script potrebbero non funzionare su nuove versioni
- **Custom code**: Analizza per implementazioni custom
- **Native**: Alcune app pinnano in native code
- **Document**: Log metodo di bypass usato

## Riferimenti

- [Frida Codeshare](https://codeshare.frida.re/)
- [Objection](https://github.com/sensepost/objection)
- [apk-mitm](https://github.com/shroudedcode/apk-mitm)
- [OWASP MSTG - Network](https://mobile-security.gitbook.io/mobile-security-testing-guide/)
