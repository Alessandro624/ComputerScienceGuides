# pytest

## Scopo

Questa guida fornisce una panoramica di pytest, il framework di testing piu popolare per Python, coprendo configurazione, fixtures, parametrizzazione e best practice.

## Prerequisiti

- Python 3.7+
- pip package manager
- Conoscenza base Python

## Installazione

```bash
pip install pytest
pip install pytest-cov  # Coverage
pip install pytest-xdist  # Parallelismo
pip install pytest-mock  # Mocking
```

---

## Struttura Progetto

```
project/
├── src/
│   └── myapp/
│       ├── __init__.py
│       └── calculator.py
├── tests/
│   ├── __init__.py
│   ├── conftest.py
│   ├── test_calculator.py
│   └── unit/
│       └── test_utils.py
├── pytest.ini
└── pyproject.toml
```

---

## Test Base

### Primo Test

```python
# tests/test_example.py

def test_addition():
    assert 1 + 1 == 2

def test_string():
    assert "hello".upper() == "HELLO"

def test_list():
    items = [1, 2, 3]
    assert len(items) == 3
    assert 2 in items
```

### Esecuzione

```bash
# Tutti i test
pytest

# File specifico
pytest tests/test_example.py

# Test specifico
pytest tests/test_example.py::test_addition

# Verbose
pytest -v

# Extra verbose
pytest -vv

# Stop al primo fallimento
pytest -x

# Ultimi N fallimenti
pytest --lf
pytest --ff
```

---

## Asserzioni

```python
# Uguaglianza
assert result == expected
assert result != unexpected

# Booleani
assert condition
assert not condition

# Contenimento
assert item in collection
assert item not in collection

# Tipo
assert isinstance(obj, MyClass)

# Eccezioni
def test_exception():
    with pytest.raises(ValueError):
        int("not a number")

def test_exception_message():
    with pytest.raises(ValueError, match="invalid literal"):
        int("abc")

# Approx per float
from pytest import approx
assert 0.1 + 0.2 == approx(0.3)
assert result == approx(expected, rel=1e-3)
```

---

## Fixtures

### Base

```python
# conftest.py o test file

import pytest

@pytest.fixture
def sample_data():
    return {"name": "Mario", "age": 30}

@pytest.fixture
def database_connection():
    conn = create_connection()
    yield conn  # Fornisce la connessione
    conn.close()  # Cleanup dopo il test

# Uso
def test_with_fixture(sample_data):
    assert sample_data["name"] == "Mario"

def test_with_db(database_connection):
    result = database_connection.query("SELECT 1")
    assert result is not None
```

### Scope

```python
@pytest.fixture(scope="function")  # Default, per ogni test
def func_fixture():
    pass

@pytest.fixture(scope="class")  # Per classe
def class_fixture():
    pass

@pytest.fixture(scope="module")  # Per modulo
def module_fixture():
    pass

@pytest.fixture(scope="session")  # Per sessione
def session_fixture():
    pass
```

### Autouse

```python
@pytest.fixture(autouse=True)
def setup_logging():
    logging.basicConfig(level=logging.DEBUG)
    yield
    logging.shutdown()
```

### Factory Fixture

```python
@pytest.fixture
def make_user():
    def _make_user(name, age=25):
        return User(name=name, age=age)
    return _make_user

def test_users(make_user):
    user1 = make_user("Mario")
    user2 = make_user("Luigi", age=28)
    assert user1.name == "Mario"
```

---

## Parametrizzazione

### Test Parametrizzati

```python
import pytest

@pytest.mark.parametrize("input,expected", [
    (1, 2),
    (2, 4),
    (3, 6),
    (4, 8),
])
def test_double(input, expected):
    assert input * 2 == expected

@pytest.mark.parametrize("a,b,expected", [
    (1, 1, 2),
    (2, 3, 5),
    (10, -5, 5),
])
def test_add(a, b, expected):
    assert a + b == expected
```

### ID Personalizzati

```python
@pytest.mark.parametrize("value", [
    pytest.param(1, id="one"),
    pytest.param(2, id="two"),
    pytest.param(3, id="three"),
])
def test_values(value):
    assert value > 0
```

### Fixture Parametrizzata

```python
@pytest.fixture(params=["mysql", "postgres", "sqlite"])
def database(request):
    db = create_db(request.param)
    yield db
    db.cleanup()

def test_query(database):
    result = database.execute("SELECT 1")
    assert result is not None
```

---

## Markers

### Markers Built-in

```python
import pytest

@pytest.mark.skip(reason="Non implementato")
def test_not_implemented():
    pass

@pytest.mark.skipif(sys.version_info < (3, 10), reason="Richiede Python 3.10+")
def test_new_feature():
    pass

@pytest.mark.xfail(reason="Bug noto")
def test_known_bug():
    assert False  # Fallimento atteso

@pytest.mark.slow
def test_slow_operation():
    time.sleep(10)
```

### Markers Personalizzati

```python
# pytest.ini
[pytest]
markers =
    slow: marks tests as slow
    integration: marks tests as integration tests
    unit: marks tests as unit tests
```

```python
@pytest.mark.integration
def test_api_call():
    pass

# Esegui solo integration
# pytest -m integration

# Escludi slow
# pytest -m "not slow"
```

---

## Mocking

### pytest-mock

```python
def test_with_mock(mocker):
    # Mock funzione
    mock_func = mocker.patch("myapp.module.external_api")
    mock_func.return_value = {"status": "ok"}
    
    result = my_function()
    
    assert result["status"] == "ok"
    mock_func.assert_called_once()

def test_mock_method(mocker):
    # Mock metodo
    mocker.patch.object(MyClass, "method", return_value=42)
    
    obj = MyClass()
    assert obj.method() == 42
```

### unittest.mock

```python
from unittest.mock import Mock, patch, MagicMock

def test_with_patch():
    with patch("myapp.requests.get") as mock_get:
        mock_get.return_value.json.return_value = {"data": "test"}
        
        result = fetch_data()
        
        assert result == {"data": "test"}

@patch("myapp.database.connect")
def test_decorated(mock_connect):
    mock_connect.return_value = MagicMock()
    # test code
```

---

## Coverage

```bash
# Installa
pip install pytest-cov

# Esegui con coverage
pytest --cov=src

# Report HTML
pytest --cov=src --cov-report=html

# Report terminale
pytest --cov=src --cov-report=term-missing

# Threshold minimo
pytest --cov=src --cov-fail-under=80
```

---

## Configurazione

### pytest.ini

```ini
[pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts = -v --tb=short
markers =
    slow: slow tests
    integration: integration tests
filterwarnings =
    ignore::DeprecationWarning
```

### pyproject.toml

```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
python_files = ["test_*.py"]
addopts = "-v --tb=short --strict-markers"
markers = [
    "slow: marks tests as slow",
    "integration: integration tests",
]

[tool.coverage.run]
source = ["src"]
omit = ["tests/*", "*/__init__.py"]

[tool.coverage.report]
exclude_lines = [
    "pragma: no cover",
    "if TYPE_CHECKING:",
]
```

### conftest.py

```python
# tests/conftest.py
import pytest

# Fixtures condivise
@pytest.fixture(scope="session")
def app():
    from myapp import create_app
    return create_app(testing=True)

@pytest.fixture
def client(app):
    return app.test_client()

# Hook personalizzati
def pytest_configure(config):
    config.addinivalue_line("markers", "e2e: end-to-end tests")
```

---

## Parallelismo

```bash
# Installa
pip install pytest-xdist

# Esegui in parallelo
pytest -n auto  # Auto-detect CPU
pytest -n 4     # 4 workers
```

---

## Comandi Utili

```bash
# Lista test senza eseguire
pytest --collect-only

# Mostra fixtures disponibili
pytest --fixtures

# Durata test
pytest --durations=10

# Output print
pytest -s

# Keyword filter
pytest -k "test_add or test_sub"
pytest -k "not slow"

# Traceback
pytest --tb=short
pytest --tb=long
pytest --tb=no
```

---

## Best Practices

- **Naming**: Usa nomi descrittivi `test_should_return_error_when_invalid`
- **Arrange-Act-Assert**: Struttura chiara dei test
- **Fixtures**: Riusa setup comune
- **Isolation**: Test indipendenti
- **Coverage**: Mantieni coverage alto ma significativo

## Riferimenti

- [pytest Documentation](https://docs.pytest.org/)
- [pytest-cov](https://pytest-cov.readthedocs.io/)
- [Real Python pytest](https://realpython.com/pytest-python-testing/)
