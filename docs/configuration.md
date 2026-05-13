# Configuration

Complete reference for django-field-encryption configuration options.

## Settings

### DATA_PROTECTION_KEYS

Required dictionary mapping key IDs to master keys:

```python
DATA_PROTECTION_KEYS = {
    'v1': 'base64-encoded-32-byte-key',
    'v2': 'another-base64-key',
}
```

Each key must be:
- 32 bytes raw, or
- 44 characters base64-encoded (represents 32 bytes)

### DATA_PROTECTION_ACTIVE_KEY_ID

The key ID used for new encryptions:

```python
DATA_PROTECTION_ACTIVE_KEY_ID = 'v1'
```

If not specified, the highest sorted key ID is used automatically.

## Key Generation

### generate_master_key()

Generates a cryptographically secure master key:

```python
from django_field_encryption import generate_master_key

key = generate_master_key()  # Returns base64-encoded 32-byte key
```

## Key Management

### Multiple Keys and Rotation

Store multiple key versions to support key rotation:

```python
DATA_PROTECTION_KEYS = {
    'v1': 'old-key-base64...',
    'v2': 'new-key-base64...',
}
DATA_PROTECTION_ACTIVE_KEY_ID = 'v2'
```

### rotate_keys()

Re-encrypt all existing data with the active key:

```python
from django_field_encryption import rotate_keys

results = rotate_keys(app_label='myapp', batch_size=500)
# {'myapp.User.ssn': {'rotated': 42, 'skipped': 10}, ...}
```

Parameters:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `app_label` | `str \| None` | `None` | Limit rotation to one app |
| `batch_size` | `int` | `1000` | Records per database query |
| `dry_run` | `bool` | `False` | Preview without writing |

Example data migration:

```python
from django.db import migrations
from django_field_encryption import rotate_keys


def rotate_forward(apps, schema_editor):
    rotate_keys(app_label='myapp', batch_size=500)


class Migration(migrations.Migration):
    dependencies = [('myapp', '0001_initial')]
    operations = [migrations.RunPython(rotate_forward, migrations.RunPython.noop)]
```

Or use the management command:

```bash
python manage.py rotate_encryption_keys --dry-run
python manage.py rotate_encryption_keys
```

### rotate_model_fields()

Rotate one or more fields on a specific model:

```python
from django_field_encryption import rotate_model_fields
from myapp.models import User

rotate_model_fields(User, field_names=['ssn'])
# {'ssn': {'rotated': 42, 'skipped': 10}}
```

Parameters:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `model` | `Model` | (required) | The Django model class |
| `field_names` | `list[str] \| None` | `None` | Fields to rotate; `None` means all encrypted fields |
| `batch_size` | `int` | `1000` | Records per database query |
| `dry_run` | `bool` | `False` | Preview without writing |

Example data migration:

```python
from django.db import migrations
from django_field_encryption import rotate_model_fields


def rotate_forward(apps, schema_editor):
    User = apps.get_model('myapp', 'User')
    rotate_model_fields(User, field_names=['ssn', 'email'])


class Migration(migrations.Migration):
    dependencies = [('myapp', '0001_initial')]
    operations = [migrations.RunPython(rotate_forward, migrations.RunPython.noop)]
```

## Configuration Functions

### get_keys_config()

Returns all configured keys:

```python
from django_field_encryption import get_keys_config

keys = get_keys_config()
# Returns: {'v1': 'key1...', 'v2': 'key2...'}
```

### get_active_key_id()

Returns the currently active key ID:

```python
from django_field_encryption import get_active_key_id

active = get_active_key_id()
# Returns: 'v1'
```

### get_master_key(key_id)

Returns the raw 32-byte key for a given key ID, wrapped in a ``MasterKey``
object to prevent accidental exposure via ``repr()`` or ``str()``:

```python
from django_field_encryption import get_master_key

key = get_master_key('v1')
raw_bytes = bytes(key)  # b'\x00\x01\x02...' (32 bytes)
```

To use the raw key material, cast with ``bytes()``. The ``MasterKey``
object also supports ``len()`` and equality comparison.

## Key Caching

The library caches derived keys in memory for performance. Clear the cache after changing configuration in tests:

```python
from django_field_encryption import FieldEncryptor, FileEncryptor

FieldEncryptor.clear_cache()
FileEncryptor.clear_cache()
```

## Environment Variables

For production, consider loading keys from environment variables:

```python
import os

DATA_PROTECTION_KEYS = {
    'v1': os.environ.get('ENCRYPTION_KEY_V1'),
}
DATA_PROTECTION_ACTIVE_KEY_ID = 'v1'
```

## Best Practices

1. **Store keys securely** - Use environment variables or secrets management
2. **Rotate keys regularly** - Schedule key rotation every 90 days
3. **Keep old keys** - Maintain previous keys for decryption during rotation
4. **Audit key usage** - Log which key version encrypts each value
5. **Never commit keys** - Never store keys in version control