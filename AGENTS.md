# AGENTS.md

## Build/Lint/Test Commands

- **Install dependencies**: `uv sync` or `pip install -e ".[dev]"`
- **Run all tests**: `uv run pytest` or `pytest`
- **Run a single test file**: `pytest tests/test_encryption.py`
- **Run a single test**: `pytest tests/test_encryption.py::TestFieldEncryptor::test_encrypt_decrypt_roundtrip`
- **Run tests by keyword**: `pytest -k "test_encrypt_decrypt_roundtrip"`
- **Run tests by class**: `pytest -k "TestFieldEncryptor"`
- **Lint**: `ruff check .`
- **Format check**: `ruff format --check .`
- **Format fix**: `ruff format .`
- **Type check**: `pyright`
- **Build package**: `python -m build`

## Project Overview

Django field-level encryption library using AES-256-GCM. Provides encrypted model fields (`EncryptedCharField`, `EncryptedTextField`, `EncryptedJSONField`), blind index fields for searchable encryption (`BlindIndexField`), encrypted file storage, and management commands for bulk encryption/decryption and key rotation. Python 3.9+, Django 4.2-7.0.

## Code Style Guidelines

### Formatting (ruff)

- **Line length**: 88 (default, but E501 is ignored so longer lines are tolerated)
- **Quote style**: Single quotes (`'`) for strings — enforced by ruff
- **Target Python**: 3.9

### Import Ordering (isort via ruff)

Managed by ruff's isort rules. First-party package is `django_field_encryption`. Order:
1. Standard library (`base64`, `os`, `threading`, `typing`, etc.)
2. Third-party (`cryptography`, `django`)
3. First-party (`django_field_encryption` / relative imports)

Use relative imports within the package (e.g., `from .encryption import FieldEncryptor`).

### Type Annotations

- Use `from typing import Any, Optional` etc. as needed
- Method signatures use type hints: `def __init__(self, *args: Any, strict: bool = False, **kwargs: Any)`
- Use `Optional[str]` for nullable params, not `str | None` (Python 3.9 compat)
- Use `dict[str, str]`, `tuple[bytes, str]` etc. for generic types (Python 3.9+ style, not `Dict`/`Tuple`)
- Use `# type: ignore[...]` for specific type errors rather than bare `# type: ignore`

### Naming Conventions

- **Classes**: PascalCase (`FieldEncryptor`, `EncryptedCharField`, `BlindIndexField`)
- **Functions/methods**: snake_case (`_derive_aes_key`, `get_prep_value`, `can_decrypt`)
- **Private module-level**: leading underscore (`_get_keys_config`, `_get_active_key_id`, `_cache_lock`)
- **Constants**: UPPER_SNAKE_CASE (`PREFIX_SEPARATOR`, `NONCE_LENGTH`, `FIELD_KEY_INFO_PREFIX`)
- **Class constants**: UPPER_SNAKE_CASE (`FILE_MAGIC`)
- **Exception classes**: PascalCase with `Error` suffix (`EncryptionError`, `DecryptionError`, `InvalidKeyError`)

### Django Conventions

- Model fields follow Django's field API: `__init__`, `from_db_value`, `to_python`, `get_prep_value`, `deconstruct`
- `deconstruct()` must return the full import path (e.g., `'django_field_encryption.fields.EncryptedCharField'`)
- Management commands live in `django_field_encryption/management/commands/`
- Django settings are namespaced with `DATA_PROTECTION_` prefix

### Error Handling

- Custom exception hierarchy: `EncryptionError` base → `ConfigurationError`, `InvalidKeyError`, `DecryptionError`, `EncryptionNotConfiguredError`
- Exceptions carry contextual attributes: `key_id`, `key_length`, `original_exception`
- Use `from e` to chain exceptions: `raise DecryptionError(...) from e`
- Fields have a `strict` mode: when `True`, exceptions propagate; when `False` (default), values pass through on error
- Use `logger.exception()` for logging failures, then re-raise as custom exceptions

### Testing Conventions

- Test files: `tests/test_*.py`
- Test classes: `Test*` prefix (e.g., `TestFieldEncryptor`, `TestBlindIndexField`)
- Test methods: `test_*` prefix
- Use `django.test.TestCase` and `override_settings` for encrypted test contexts
- Define `TEST_MASTER_KEY` and `ENCRYPTION_SETTINGS` at module level for reuse
- Call `FieldEncryptor.clear_cache()` in `setUp` and `setUpClass` to avoid stale key caches between tests
- Use SQLite in-memory database (`tests/settings.py`)
- Dynamic model creation for tests uses `class Meta: app_label = 'tests'`
- Use `assert` statements in simple cases, `self.assert*` methods from Django's TestCase

### Module Structure

- Public API is exported via `django_field_encryption/__init__.py` with `__all__`
- Lazy imports for admin mixins via `__getattr__` to avoid importing Django at module load
- Internal helpers use leading underscore (`_get_master_key`, `_derive_aes_key`)
- Public wrappers without underscore (`get_master_key`, `get_active_key_id`, `get_keys_config`)
- `py.typed` marker file included for PEP 561 type checking support