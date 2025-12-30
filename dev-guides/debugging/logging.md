# Logging

## Scopo

Questa guida fornisce una panoramica delle best practices di logging in diverse tecnologie e linguaggi di programmazione.

## Prerequisiti

- Conoscenza base programmazione
- Comprensione applicazioni server-side

---

## Livelli di Log

| Livello | Uso | Esempio |
|---------|-----|---------|
| TRACE | Debug dettagliato | Valori variabili in loop |
| DEBUG | Info sviluppo | Query SQL, parametri funzioni |
| INFO | Eventi normali | Startup, shutdown, request |
| WARN | Situazioni anomale | Retry, fallback, deprecation |
| ERROR | Errori gestiti | Exception caught, validazione |
| FATAL | Errori critici | App crash, risorse mancanti |

---

## Python (logging)

### Base

```python
import logging

# Configurazione base
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

logger.debug("Debug message")
logger.info("Info message")
logger.warning("Warning message")
logger.error("Error message")
logger.critical("Critical message")
```

### Configurazione Avanzata

```python
import logging
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler

# Logger
logger = logging.getLogger('myapp')
logger.setLevel(logging.DEBUG)

# Formatter
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Console handler
console = logging.StreamHandler()
console.setLevel(logging.INFO)
console.setFormatter(formatter)

# File handler (rotating)
file_handler = RotatingFileHandler(
    'app.log',
    maxBytes=10*1024*1024,  # 10MB
    backupCount=5
)
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)

# Time-based rotation
time_handler = TimedRotatingFileHandler(
    'app.log',
    when='midnight',
    interval=1,
    backupCount=30
)

# Add handlers
logger.addHandler(console)
logger.addHandler(file_handler)
```

### Structured Logging (structlog)

```python
import structlog

structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
)

logger = structlog.get_logger()

logger.info("user_login", user_id=123, ip="192.168.1.1")
# {"event": "user_login", "user_id": 123, "ip": "192.168.1.1", "level": "info", "timestamp": "2024-01-15T10:30:00Z"}
```

---

## Java (SLF4J + Logback)

### Dipendenze Maven

```xml
<dependency>
    <groupId>ch.qos.logback</groupId>
    <artifactId>logback-classic</artifactId>
    <version>1.4.14</version>
</dependency>
```

### Uso

```java
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MyClass {
    private static final Logger logger = LoggerFactory.getLogger(MyClass.class);
    
    public void doSomething() {
        logger.debug("Debug message");
        logger.info("Processing user: {}", userId);
        logger.warn("Retry attempt {} of {}", attempt, maxRetries);
        logger.error("Error processing", exception);
    }
}
```

### logback.xml

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <appender name="CONSOLE" class="ch.qos.logback.core.ConsoleAppender">
        <encoder>
            <pattern>%d{yyyy-MM-dd HH:mm:ss} [%thread] %-5level %logger{36} - %msg%n</pattern>
        </encoder>
    </appender>
    
    <appender name="FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
        <file>logs/app.log</file>
        <rollingPolicy class="ch.qos.logback.core.rolling.TimeBasedRollingPolicy">
            <fileNamePattern>logs/app.%d{yyyy-MM-dd}.log</fileNamePattern>
            <maxHistory>30</maxHistory>
        </rollingPolicy>
        <encoder>
            <pattern>%d{yyyy-MM-dd HH:mm:ss} [%thread] %-5level %logger{36} - %msg%n</pattern>
        </encoder>
    </appender>
    
    <root level="INFO">
        <appender-ref ref="CONSOLE" />
        <appender-ref ref="FILE" />
    </root>
    
    <logger name="com.myapp" level="DEBUG" />
</configuration>
```

---

## JavaScript/Node.js

### Winston

```javascript
const winston = require('winston');

const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.File({ filename: 'error.log', level: 'error' }),
        new winston.transports.File({ filename: 'combined.log' })
    ]
});

if (process.env.NODE_ENV !== 'production') {
    logger.add(new winston.transports.Console({
        format: winston.format.simple()
    }));
}

logger.info('Info message', { userId: 123 });
logger.error('Error occurred', { error: err.message });
```

### Pino (High Performance)

```javascript
const pino = require('pino');

const logger = pino({
    level: process.env.LOG_LEVEL || 'info',
    transport: {
        target: 'pino-pretty',
        options: {
            colorize: true
        }
    }
});

logger.info({ userId: 123 }, 'User logged in');
logger.error({ err }, 'Error occurred');
```

---

## Go

### Standard Library

```go
package main

import (
    "log"
    "os"
)

func main() {
    // File logging
    file, _ := os.OpenFile("app.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
    log.SetOutput(file)
    log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
    
    log.Println("Info message")
    log.Printf("User %d logged in", userId)
    log.Fatal("Fatal error")
}
```

### Zap (Uber)

```go
package main

import "go.uber.org/zap"

func main() {
    logger, _ := zap.NewProduction()
    defer logger.Sync()
    
    sugar := logger.Sugar()
    sugar.Infow("User login",
        "user_id", 123,
        "ip", "192.168.1.1",
    )
    
    // Structured
    logger.Info("User login",
        zap.Int("user_id", 123),
        zap.String("ip", "192.168.1.1"),
    )
}
```

---

## Best Practices

### Cosa Loggare

```
DO:
- Request/Response (senza dati sensibili)
- Errori con stack trace
- Performance metrics
- Security events
- State changes importanti

DON'T:
- Password, tokens, chiavi
- Dati personali (GDPR)
- Dati sanitari (HIPAA)
- Numeri carte di credito
```

### Formato

```json
{
  "timestamp": "2024-01-15T10:30:00.123Z",
  "level": "INFO",
  "service": "user-service",
  "traceId": "abc123",
  "message": "User logged in",
  "context": {
    "userId": 123,
    "method": "POST",
    "path": "/api/login",
    "duration": 45
  }
}
```

### Correlazione

```python
import uuid

class RequestContext:
    def __init__(self):
        self.request_id = str(uuid.uuid4())
        self.user_id = None

# Passa request_id in tutti i log
logger.info("Processing request", extra={
    "request_id": context.request_id,
    "user_id": context.user_id
})
```

---

## Log Aggregation

### Stack ELK

```yaml
# docker-compose.yml
services:
  elasticsearch:
    image: elasticsearch:8.11.0
    
  logstash:
    image: logstash:8.11.0
    
  kibana:
    image: kibana:8.11.0
```

### Fluentd

```
# fluent.conf
<source>
  @type tail
  path /var/log/app/*.log
  tag app.logs
</source>

<match app.**>
  @type elasticsearch
  host elasticsearch
  port 9200
</match>
```

---

## Metriche

```python
import time
from functools import wraps

def log_execution_time(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        duration = time.time() - start
        logger.info(f"{func.__name__} executed", extra={
            "duration_ms": duration * 1000
        })
        return result
    return wrapper
```

---

## Best Practices Summary

- **Livelli appropriati**: Usa livelli corretti
- **Structured logging**: JSON per parsing
- **Correlation ID**: Traccia request
- **No sensitive data**: Mai loggare secrets
- **Rotation**: Ruota file log
- **Centralized**: Aggrega log centralmente

## Riferimenti

- [Python logging](https://docs.python.org/3/library/logging.html)
- [Logback](https://logback.qos.ch/)
- [Winston](https://github.com/winstonjs/winston)
- [12 Factor App - Logs](https://12factor.net/logs)
