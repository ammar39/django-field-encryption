## Features Demonstrated

### 1. Encrypted Fields
- **EncryptedCharField** - SSN and other short sensitive text
- **EncryptedTextField** - Private notes and longer content
- **EncryptedJSONField** - Structured preferences data

Navigate to `/profiles/` to create and view profiles. The detail view shows both decrypted data and raw encrypted values.

### 2. File Encryption
- **EncryptedFileStorage** - Files are encrypted at rest with AES-256-GCM

Navigate to `/documents/` to upload files. Files are stored encrypted on disk but decrypted transparently on download.

### 3. Key Rotation
- Multiple keys configured (`v1` and `v2`)
- Switch active keys without losing data
- Re-encrypt existing data with the new key

Navigate to `/key-rotation/` to see key usage analysis and perform rotation.

## Configuration

The demo uses two pre-generated encryption keys in `demo/settings.py`:

```python
DATA_PROTECTION_KEYS = {
    'v1': 'Dzx_c7TFOSXCA_IuFXs4kqeoHJjs2Ix4b8E2wORqP0k=',
    'v2': 'v1MC4SRAU7VjUJWYMpA3N7rG5GGY6QybDBBcUYEZhv4=',
}
DATA_PROTECTION_ACTIVE_KEY_ID = 'v1'
```

**Warning**: These are demo keys only. Never use them in production!

## Database

Uses SQLite (`db.sqlite3`) for simplicity.
