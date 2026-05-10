# django-field-encryption

[![PyPI](https://img.shields.io/pypi/v/django-field-encryption.svg)](https://pypi.org/project/django-field-encryption/)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/django-field-encryption.svg)](https://pypi.org/project/django-field-encryption/)

Field-level and file encryption for Django using AES-256-GCM with automatic key rotation support.

## Features

- **Field-level encryption**: Encrypt sensitive data in Django model fields (CharField, TextField, JSONField, IntegerField, DateField, DateTimeField, EmailField)
- **File encryption**: Encrypt uploaded files with dedicated storage backend
- **Blind index fields**: Searchable encrypted fields via HMAC-SHA256 hashes
- **Automatic key rotation**: Seamlessly rotate encryption keys without data migration
- **Key derivation**: Separate keys for fields, files, and hashes using HKDF
- **Tamper detection**: AES-GCM provides built-in authentication
- **Multiple key support**: Manage multiple encryption key versions
- **Django admin integration**: Mask encrypted fields and search via blind indexes

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
from django.db import models
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

All encrypted fields store data as `TextField` in the database. Lookups (except `isnull`) are blocked by default -- use `BlindIndexField` for searchable encrypted fields.

### EncryptedCharField

Encrypted character field stored as TextField:

```python
from django_field_encryption import EncryptedCharField

class UserProfile(models.Model):
    ssn = EncryptedCharField(max_length=20)
    credit_card = EncryptedCharField(max_length=16)
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
obj = Settings.objects.create(
    preferences={'theme': 'dark', 'notifications': True}
)
# Automatically serialized, encrypted, and stored
```

### EncryptedIntegerField

Encrypted integer field:

```python
from django_field_encryption import EncryptedIntegerField

class Account(models.Model):
    balance = EncryptedIntegerField()
```

### EncryptedDateField / EncryptedDateTimeField

Encrypted date and datetime fields:

```python
from django_field_encryption import EncryptedDateField, EncryptedDateTimeField

class Event(models.Model):
    event_date = EncryptedDateField()
    created_at = EncryptedDateTimeField()
```

### EncryptedEmailField

Encrypted email field:

```python
from django_field_encryption import EncryptedEmailField

class Contact(models.Model):
    email = EncryptedEmailField(max_length=255)
```

### EncryptedFieldMixin

Base mixin for creating custom encrypted fields:

```python
from django.db import models
from django_field_encryption import EncryptedFieldMixin

class EncryptedURLField(EncryptedFieldMixin, models.URLField):
    pass
```

The mixin accepts a `strict` parameter (default `True`). When `strict=False`, decryption failures return the raw value instead of raising an exception.

## Blind Index Fields

Enable unique lookups on encrypted fields without decrypting:

```python
from django_field_encryption import EncryptedCharField, BlindIndexField

class UserProfile(models.Model):
    email = EncryptedCharField(max_length=255)
    email_hash = BlindIndexField('email', unique=True, db_index=True)
```

The hash is auto-computed on save via a `pre_save` signal. Lookup by hash:

```python
from django_field_encryption import compute_hash

user = UserProfile.objects.get(email_hash=compute_hash('user@example.com'))
```

Note: `bulk_create` and `bulk_update` do not fire `pre_save` signals -- hashes must be computed manually for bulk operations.

## File Encryption

### EncryptedFileStorage

Use the encrypted file storage for sensitive file uploads:

```python
from django.db import models
from django_field_encryption import EncryptedFileStorage

class Document(models.Model):
    file = models.FileField(storage=EncryptedFileStorage())
```

Or use the pre-configured instance:

```python
from django_field_encryption import encrypted_file_storage

class Document(models.Model):
    file = models.FileField(storage=encrypted_file_storage)
```

### BaseEncryptedStorage

Wrap any Django `Storage` backend with transparent encryption:

```python
from django_field_encryption import BaseEncryptedStorage
from storages.backends.s3boto3 import S3Boto3Storage

class EncryptedS3Storage(BaseEncryptedStorage):
    def __init__(self, **kwargs):
        super().__init__(underlying_storage=S3Boto3Storage(), **kwargs)
```

## Migrations

### Adding encryption to a field

Adding encryption requires three migrations: add the encrypted column, backfill with encrypted data, then remove the old column.

**1. Add the encrypted field alongside the plaintext field:**

```python
class UserProfile(models.Model):
    ssn = models.CharField(max_length=20)
    ssn_encrypted = EncryptedCharField(max_length=20, null=True, blank=True)
```

```bash
python manage.py makemigrations myapp && python manage.py migrate myapp
```

**2. Backfill encrypted data:**

```bash
python manage.py makemigrations --empty myapp --name encrypt_ssn
```

Edit the migration:

```python
from django.db import migrations
from django_field_encryption import FieldEncryptor


def encrypt_ssn(apps, schema_editor):
    UserProfile = apps.get_model('myapp', 'UserProfile')
    for obj in UserProfile.objects.iterator():
        if obj.ssn:
            obj.ssn_encrypted = FieldEncryptor.encrypt(obj.ssn)
            obj.save(update_fields=['ssn_encrypted'])


def reverse_encrypt_ssn(apps, schema_editor):
    UserProfile = apps.get_model('myapp', 'UserProfile')
    for obj in UserProfile.objects.iterator():
        if obj.ssn_encrypted:
            obj.ssn = FieldEncryptor.decrypt(obj.ssn_encrypted)
            obj.save(update_fields=['ssn'])


class Migration(migrations.Migration):
    dependencies = [('myapp', '0002_userprofile_ssn_encrypted')]
    operations = [migrations.RunPython(encrypt_ssn, reverse_encrypt_ssn)]
```

```bash
python manage.py migrate myapp
```

**3. Remove the old plaintext field:**

```python
class UserProfile(models.Model):
    ssn = EncryptedCharField(max_length=20)
```

```bash
python manage.py makemigrations myapp && python manage.py migrate myapp
```

### Removing encryption from a field

Reverse the three-migration pattern: add a plaintext column, decrypt into it, then remove the encrypted column.

```python
def decrypt_ssn(apps, schema_editor):
    UserProfile = apps.get_model('myapp', 'UserProfile')
    for obj in UserProfile.objects.iterator():
        if obj.ssn:
            obj.ssn_plaintext = FieldEncryptor.decrypt(obj.ssn)
            obj.save(update_fields=['ssn_plaintext'])
```

### Switching encrypted field types

All encrypted fields store as `TextField`, so no data migration is needed -- just change the model definition and run `makemigrations`:

```python
# Before
secret = EncryptedCharField(max_length=200)
# After
secret = EncryptedTextField()
```

### Key rotation

```bash
python manage.py rotate_encryption_keys --dry-run
python manage.py rotate_encryption_keys
python manage.py rotate_encryption_keys --app-label myapp --batch-size 500
```

For selective rotation:

```python
from django_field_encryption import FieldEncryptor

for obj in MyModel.objects.all():
    new_value = FieldEncryptor.rotate_value(obj.secret)
    if new_value is not None:
        obj.secret = new_value
        obj.save(update_fields=['secret'])
```

After rotation, recompute blind index hashes:

```python
from django_field_encryption import compute_hash

for obj in MyModel.objects.all():
    obj.email_hash = compute_hash(obj.email)
    obj.save(update_fields=['email_hash'])
```

## Django Admin

Use the provided mixins to integrate encrypted fields with the Django admin:

```python
from django.contrib import admin
from django_field_encryption import EncryptedFieldAdminMixin, EncryptedSearchMixin
from .models import UserProfile


@admin.register(UserProfile)
class UserProfileAdmin(EncryptedSearchMixin, EncryptedFieldAdminMixin, admin.ModelAdmin):
    list_display = ('name', 'display_ssn', 'created_at')
    search_fields = ('name', 'ssn_hash')
    encrypted_search_fields = {'ssn': 'ssn_hash'}

    encrypted_field_mask = '***encrypted***'
    show_encrypted_in_readonly = True
    exclude_encrypted_from_search = True
```

- **`EncryptedFieldAdminMixin`** -- masks encrypted fields in `list_display`, moves them to `readonly_fields`, and excludes them from `search_fields`.
- **`EncryptedSearchMixin`** -- enables searching by blind index hash via `encrypted_search_fields = {'field_name': 'hash_field_name'}`. If the hash field name is `None`, it defaults to `'{field_name}_hash'`.

Both mixins work with any `ModelAdmin` that inherits them.

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

Compute a deterministic HMAC-SHA256 hash for blind indexing:

```python
from django_field_encryption import compute_hash

hash_value = compute_hash('user@example.com')
# Returns: 64-character hex string
```

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

### Exceptions

```python
from django_field_encryption import (
    EncryptionError,
    ConfigurationError,
    InvalidKeyError,
    DecryptionError,
    EncryptionNotConfiguredError,
)
```

All exceptions inherit from `EncryptionError`. `ConfigurationError`, `InvalidKeyError`, and `DecryptionError` accept optional `key_id` and other contextual attributes.

## Compatibility

- Django 4.2 LTS is fully supported
- Django 5.0+ supported
- Django 6.x supported (constraint is `<7.0`)

## Security Notes

- Keys are 32 bytes (256 bits) for AES-256
- Uses AES-GCM (Galois/Counter Mode) for authenticated encryption
- Each encryption generates a unique 12-byte random nonce
- Field, file, and hash keys are derived separately using HKDF
- The library does not encrypt at rest -- data is encrypted/decrypted in memory only
- **High-volume deployments**: Rotate keys before reaching ~2^32 encryptions per key to avoid nonce collision risk. See [docs/security.md](docs/security.md) for details.

## License

MIT
