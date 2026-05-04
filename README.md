# django-field-encryption

Field-level and file encryption for Django using AES-256-GCM with automatic key rotation support.

## Features

- **Field-level encryption**: Encrypt sensitive data in Django model fields
- **File encryption**: Encrypt uploaded files with dedicated storage backend
- **Automatic key rotation**: Seamlessly rotate encryption keys without data migration
- **Key derivation**: Separate keys for fields and files using HKDF
- **Tamper detection**: AES-GCM provides built-in authentication
- **Multiple key support**: Manage multiple encryption key versions

## Installation

```bash
pip install django-field-encryption
```

## Quick Start

1. Add to your Django settings:

```python
DATA_PROTECTION_KEYS = {
    'v1': 'your-base64-encoded-32-byte-key',
}
DATA_PROTECTION_ACTIVE_KEY_ID = 'v1'
```

2. Use the encrypted fields:

```python
from django_field_encryption import EncryptedCharField, EncryptedTextField

class MyModel(models.Model):
    secret_name = EncryptedCharField(max_length=100)
    secret_notes = EncryptedTextField()
```

## Configuration

### Generate a Master Key

```python
from django_field_encryption import generate_master_key

key = generate_master_key()  # Returns base64-encoded 32-byte key
```

### Multiple Keys and Key Rotation

```python
DATA_PROTECTION_KEYS = {
    'v1': 'old-key-base64...',
    'v2': 'new-key-base64...',
}
DATA_PROTECTION_ACTIVE_KEY_ID = 'v2'
```

When rotating to a new key, existing encrypted data can be re-encrypted:

```python
from django_field_encryption import FieldEncryptor

# Re-encrypt with the active key
rotated_value = FieldEncryptor.rotate_value(old_encrypted_value)
```

## Field Types

### EncryptedCharField

Encrypted character field stored as TextField:

```python
from django_field_encryption import EncryptedCharField

class UserProfile(models.Model):
    ssn = EncryptedCharField(max_length=20)
    credit_card = EncryptedCharField(char_max_length=16)
```

### EncryptedTextField

Encrypted text field for longer content:

```python
from django_field_encryption import EncryptedTextField

class Document(models.Model):
    content = EncryptedTextField()
    private_notes = EncryptedTextField()
```

### EncryptedJSONField

Encrypted JSON field with automatic serialization:

```python
from django_field_encryption import EncryptedJSONField

class Settings(models.Model):
    preferences = EncryptedJSONField()
```

```python
# Usage
obj = MyModel.objects.create(
    preferences={'theme': 'dark', 'notifications': True}
)
# Automatically serialized, encrypted, and stored
```

## File Encryption

### EncryptedFileStorage

Use the encrypted file storage for sensitive file uploads:

```python
from django_field_encryption import EncryptedFileStorage
from django.db import models

class Document(models.Model):
    file = models.FileField(storage=EncryptedFileStorage())
```

Or use the pre-configured instance:

```python
from django_field_encryption import encrypted_file_storage

class Document(models.Model):
    file = models.FileField(storage=encrypted_file_storage)
```

## API Reference

### FieldEncryptor

Low-level encryption/decryption operations:

```python
from django_field_encryption import FieldEncryptor

# Encrypt
encrypted = FieldEncryptor.encrypt('sensitive data')
# Returns: 'v1:base64encoded...'

# Decrypt
decrypted = FieldEncryptor.decrypt(encrypted)
# Returns: 'sensitive data'

# Check if value is encrypted with a known key
can_decrypt = FieldEncryptor.can_decrypt(encrypted)  # True/False

# Rotate to active key
rotated = FieldEncryptor.rotate_value(encrypted)
# Returns re-encrypted value or None if already using active key

# Clear key cache (call after changing settings in tests)
FieldEncryptor.clear_cache()
```

### FileEncryptor

File-level encryption:

```python
from django_field_encryption import FileEncryptor

# Encrypt bytes
encrypted, key_id = FileEncryptor.encrypt(b'sensitive file content')
# Returns: (b'ENC2...', 'v1')

# Decrypt
decrypted = FileEncryptor.decrypt(encrypted)
# Returns: b'sensitive file content'

# Check if data is encrypted
is_enc = FileEncryptor.is_encrypted(encrypted)  # True/False
```

### compute_hash

Compute a deterministic hash for indexing (without encryption):

```python
from django_field_encryption import compute_hash

hash_value = compute_hash('29901012345678')
# Returns: 64-character hex string
```

### BlindIndexField

Enable unique lookups on encrypted fields without decrypting:

```python
from django_field_encryption import EncryptedCharField, BlindIndexField

class UserProfile(models.Model):
    email = EncryptedCharField(max_length=255)
    email_hash = BlindIndexField('email', unique=True, db_index=True)

# Lookup by hash
from django_field_encryption import compute_hash
user = UserProfile.objects.get(email_hash=compute_hash('user@example.com'))
```

The hash is auto-computed on save via a `pre_save` signal. Note that `bulk_create` and `bulk_update` do not trigger signals — hashes must be computed manually for bulk operations.

### generate_master_key

Generate a cryptographically secure master key:

```python
from django_field_encryption import generate_master_key

key = generate_master_key()
# Returns: base64-encoded 32-byte key
```

### Configuration Functions

```python
from django_field_encryption import (
    get_keys_config,
    get_active_key_id,
    get_master_key,
)

keys = get_keys_config()          # Returns dict of key_id -> key
active_key = get_active_key_id()  # Returns currently active key_id
master_key = get_master_key('v1') # Returns raw 32-byte key for key_id
```

## Compatibility

| Python | Django |
|--------|--------|
| 3.9    | 4.2, 5.x |
| 3.10   | 4.2, 5.x |
| 3.11   | 4.2, 5.x |
| 3.12   | 4.2, 5.x |

- Django 4.2 LTS is fully supported
- Django 5.0+ supported
- Will support Django 6.x when released (constraint is `<7.0`)

## Security Notes

- Keys are 32 bytes (256 bits) for AES-256
- Uses AES-GCM (Galois/Counter Mode) for authenticated encryption
- Each encryption generates a unique 12-byte random nonce
- Field and file keys are derived separately using HKDF
- The library does not encrypt at rest - data is encrypted/decrypted in memory only
- **High-volume deployments**: Rotate keys before reaching ~2³² encryptions per key to avoid nonce collision risk. See [docs/security.md](docs/security.md) for details.

## License

MIT