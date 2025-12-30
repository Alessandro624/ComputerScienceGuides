# REST API Design

## Scopo

Questa guida fornisce le best practices per progettare REST API consistenti, intuitive e manutenibili.

## Prerequisiti

- Conoscenza HTTP/HTTPS
- Comprensione client-server
- JSON

---

## Principi REST

| Principio | Descrizione |
|-----------|-------------|
| Stateless | Ogni richiesta contiene tutte le info necessarie |
| Client-Server | Separazione UI e data storage |
| Cacheable | Risposte devono definire se cacheable |
| Uniform Interface | Interfaccia uniforme tra componenti |
| Layered System | Architettura a livelli |

---

## Metodi HTTP

| Metodo | CRUD | Idempotente | Safe | Uso |
|--------|------|-------------|------|-----|
| GET | Read | Si | Si | Recupera risorsa |
| POST | Create | No | No | Crea risorsa |
| PUT | Update | Si | No | Sostituisce risorsa |
| PATCH | Update | No | No | Aggiorna parzialmente |
| DELETE | Delete | Si | No | Elimina risorsa |

---

## URL Design

### Buone Pratiche

```
# Nomi plurali per collezioni
GET /users
GET /users/123
GET /users/123/orders

# Sostantivi, non verbi
GET /users          # Corretto
GET /getUsers       # Sbagliato
GET /getAllUsers    # Sbagliato

# Lowercase con trattini
GET /user-profiles  # Corretto
GET /userProfiles   # Evitare
GET /user_profiles  # Evitare

# Nesting per relazioni
GET /users/123/orders
GET /users/123/orders/456

# Max 2-3 livelli nesting
GET /users/123/orders/456/items  # Ok
GET /stores/1/shelves/2/products/3/reviews  # Troppo
```

### Versioning

```
# URL path (consigliato)
GET /api/v1/users
GET /api/v2/users

# Header
GET /api/users
Accept: application/vnd.api.v1+json

# Query parameter
GET /api/users?version=1
```

---

## Status Codes

### 2xx Success

| Code | Nome | Uso |
|------|------|-----|
| 200 | OK | Successo generico |
| 201 | Created | Risorsa creata |
| 204 | No Content | Successo senza body |

### 3xx Redirection

| Code | Nome | Uso |
|------|------|-----|
| 301 | Moved Permanently | URL cambiato |
| 304 | Not Modified | Cache valida |

### 4xx Client Error

| Code | Nome | Uso |
|------|------|-----|
| 400 | Bad Request | Richiesta malformata |
| 401 | Unauthorized | Non autenticato |
| 403 | Forbidden | Non autorizzato |
| 404 | Not Found | Risorsa non trovata |
| 405 | Method Not Allowed | Metodo non supportato |
| 409 | Conflict | Conflitto stato |
| 422 | Unprocessable Entity | Validazione fallita |
| 429 | Too Many Requests | Rate limit |

### 5xx Server Error

| Code | Nome | Uso |
|------|------|-----|
| 500 | Internal Server Error | Errore generico |
| 502 | Bad Gateway | Upstream error |
| 503 | Service Unavailable | Servizio non disponibile |
| 504 | Gateway Timeout | Timeout upstream |

---

## Request/Response Format

### Request Headers

```http
POST /api/v1/users HTTP/1.1
Host: api.example.com
Content-Type: application/json
Accept: application/json
Authorization: Bearer <token>
X-Request-ID: uuid-here
```

### Response Headers

```http
HTTP/1.1 200 OK
Content-Type: application/json
X-Request-ID: uuid-here
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1609459200
```

### JSON Response

```json
{
  "data": {
    "id": 123,
    "type": "user",
    "attributes": {
      "name": "Mario Rossi",
      "email": "mario@example.com",
      "createdAt": "2024-01-15T10:30:00Z"
    }
  },
  "meta": {
    "requestId": "abc-123"
  }
}
```

---

## Collezioni e Paginazione

### Paginazione Offset

```
GET /api/users?page=2&limit=20
```

```json
{
  "data": [...],
  "meta": {
    "currentPage": 2,
    "perPage": 20,
    "totalPages": 10,
    "totalCount": 195
  },
  "links": {
    "self": "/api/users?page=2&limit=20",
    "first": "/api/users?page=1&limit=20",
    "prev": "/api/users?page=1&limit=20",
    "next": "/api/users?page=3&limit=20",
    "last": "/api/users?page=10&limit=20"
  }
}
```

### Paginazione Cursor

```
GET /api/users?cursor=abc123&limit=20
```

```json
{
  "data": [...],
  "meta": {
    "hasMore": true
  },
  "links": {
    "next": "/api/users?cursor=xyz789&limit=20"
  }
}
```

---

## Filtering, Sorting, Search

### Filtering

```
GET /api/users?status=active
GET /api/users?role=admin&status=active
GET /api/users?age[gte]=18&age[lte]=65
GET /api/users?createdAt[gte]=2024-01-01
```

### Sorting

```
GET /api/users?sort=name           # ASC
GET /api/users?sort=-createdAt     # DESC
GET /api/users?sort=lastName,firstName
GET /api/users?sort=-createdAt,name
```

### Search

```
GET /api/users?q=mario
GET /api/users?search=mario
GET /api/users?filter[name][contains]=mario
```

### Field Selection

```
GET /api/users?fields=id,name,email
GET /api/users?fields[users]=id,name&fields[orders]=id,total
```

---

## Error Handling

### Struttura Errore

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "The request contains invalid data",
    "details": [
      {
        "field": "email",
        "message": "Invalid email format"
      },
      {
        "field": "age",
        "message": "Must be greater than 0"
      }
    ],
    "requestId": "abc-123",
    "documentation": "https://api.example.com/docs/errors#VALIDATION_ERROR"
  }
}
```

### Errori Comuni

```json
// 400 Bad Request
{
  "error": {
    "code": "INVALID_JSON",
    "message": "Request body is not valid JSON"
  }
}

// 401 Unauthorized
{
  "error": {
    "code": "AUTHENTICATION_REQUIRED",
    "message": "Authentication token is missing or invalid"
  }
}

// 404 Not Found
{
  "error": {
    "code": "RESOURCE_NOT_FOUND",
    "message": "User with ID 123 not found"
  }
}

// 429 Too Many Requests
{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Too many requests. Please retry after 60 seconds",
    "retryAfter": 60
  }
}
```

---

## Autenticazione

### Bearer Token

```http
GET /api/users HTTP/1.1
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

### API Key

```http
GET /api/users HTTP/1.1
X-API-Key: your-api-key-here
```

---

## HATEOAS

```json
{
  "data": {
    "id": 123,
    "name": "Mario Rossi",
    "email": "mario@example.com"
  },
  "links": {
    "self": "/api/users/123",
    "orders": "/api/users/123/orders",
    "update": "/api/users/123",
    "delete": "/api/users/123"
  },
  "actions": {
    "update": {
      "method": "PUT",
      "href": "/api/users/123"
    },
    "delete": {
      "method": "DELETE",
      "href": "/api/users/123"
    }
  }
}
```

---

## Esempi Completi

### CRUD Users

```http
# Lista utenti
GET /api/v1/users?page=1&limit=10&sort=-createdAt

# Singolo utente
GET /api/v1/users/123

# Crea utente
POST /api/v1/users
Content-Type: application/json

{
  "name": "Mario Rossi",
  "email": "mario@example.com",
  "password": "secure123"
}

# Aggiorna utente (completo)
PUT /api/v1/users/123
Content-Type: application/json

{
  "name": "Mario Rossi Updated",
  "email": "mario.new@example.com"
}

# Aggiorna utente (parziale)
PATCH /api/v1/users/123
Content-Type: application/json

{
  "name": "Mario Rossi Updated"
}

# Elimina utente
DELETE /api/v1/users/123
```

### Response Examples

```json
// POST /api/v1/users - 201 Created
{
  "data": {
    "id": 124,
    "name": "Mario Rossi",
    "email": "mario@example.com",
    "createdAt": "2024-01-15T10:30:00Z"
  },
  "links": {
    "self": "/api/v1/users/124"
  }
}

// GET /api/v1/users - 200 OK
{
  "data": [
    {"id": 1, "name": "User 1", ...},
    {"id": 2, "name": "User 2", ...}
  ],
  "meta": {
    "totalCount": 100,
    "page": 1,
    "perPage": 10
  }
}

// DELETE /api/v1/users/123 - 204 No Content
(empty body)
```

---

## Best Practices

- **Consistenza**: Mantieni naming e strutture uniformi
- **Versioning**: Versiona API dal giorno 1
- **Documentation**: Documenta con OpenAPI/Swagger
- **Validation**: Valida input rigorosamente
- **Rate Limiting**: Proteggi da abusi
- **Idempotency**: Supporta chiavi idempotency per POST

## Riferimenti

- [REST API Tutorial](https://restfulapi.net/)
- [HTTP Status Codes](https://httpstatuses.com/)
- [JSON:API Specification](https://jsonapi.org/)
- [OpenAPI Specification](https://swagger.io/specification/)
