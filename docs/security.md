# Security Notes

Important security considerations when using django-field-encryption.

## Cryptographic Details

### Algorithm

- **Cipher**: AES-256-GCM (Galois/Counter Mode)
- **Key derivation**: HKDF-SHA256
- **Key size**: 256 bits (32 bytes)
- **Nonce size**: 96 bits (12 bytes)
- **Authentication tag**: 128 bits (16 bytes)

### Key Derivation

All derived keys use **HKDF-SHA256** (RFC 5869) with the following parameters:

```
derived_key = HKDF(
    algorithm = SHA256,
    length    = 32 bytes (AES-256),
    salt      = SHA256(key_id),
    info      = purpose_prefix + key_id,
).derive(master_key)
```

| Parameter | Value | Purpose |
|-----------|-------|---------|
| **IKM** | 32-byte master key | Root secret from `DATA_PROTECTION_KEYS` |
| **Salt** | `SHA256(key_id)` | Domain separation per key version |
| **Info** | `{purpose_prefix}{key_id}` | Purpose binding (field, file, or hash) |
| **Length** | 32 bytes | Output key size for AES-256 |

#### Three Isolated Key Domains

Each key ID produces three **cryptographically isolated** derived keys via distinct `info` prefixes:

```
Master Key (key_id='v1')
    |
    +-- HKDF(..., info=b'data-protection-field-v1') → AES-256 field key
    +-- HKDF(..., info=b'data-protection-file-v1')  → AES-256 file key
    +-- HKDF(..., info=b'data-protection-hash-v1')  → HMAC-SHA256 hash key
```

| Prefix | Used By |
|--------|---------|
| `data-protection-field-` | `FieldEncryptor` — model field encryption |
| `data-protection-file-` | `FileEncryptor` — file/blob encryption |
| `data-protection-hash-` | `compute_hash()` — blind index HMAC |

This ensures:
- Field encryption, file encryption, and blind index hashing use different keys
- Each key version has a unique set of derived keys
- Compromise of one derived key does not affect the others
- The same master key can safely serve all three purposes

#### Key Hierarchy

The hierarchy is **flat** — there is no per-field or per-record key derivation. All fields encrypted under the same key ID share the same derived AES key. Ciphertext uniqueness for repeated plaintexts comes from the random 12-byte nonce generated via `os.urandom(12)` on each encryption.

Derived keys are cached in thread-safe module-level dictionaries to avoid repeated HKDF computation.

## Security Properties

### Confidentiality

- Data is encrypted with AES-256-GCM
- Without the key, data is indistinguishable from random

### Integrity

- AES-GCM authentication detects tampering
- Modified ciphertext fails decryption

### Non-replay

- Each encryption uses a unique random nonce
- Same plaintext encrypts to different ciphertext

### Nonce Uniqueness and Birthday Bound

AES-GCM requires that every nonce be unique under a given key. This library
uses `os.urandom(12)` to generate random 96-bit nonces. While the probability
of collision is extremely low for small datasets, the **birthday bound** means
collision risk becomes non-negligible at scale:

| Encryptions per key | Approximate collision probability |
|---------------------|-----------------------------------|
| 10⁶ (1M)           | ~10⁻¹⁶ (negligible)              |
| 10⁹ (1B)           | ~10⁻¹⁰ (still negligible)        |
| 2³² (~4.3B)        | ~10⁻⁸ (NIST recommended limit)   |
| 2⁴⁸                | ~50% (birthday bound)            |

**Nonce reuse under the same key is catastrophic** — it breaks both
confidentiality and authenticity of AES-GCM.

#### Mitigation

- **HKDF domain separation**: Field keys and file keys are derived separately,
  so the encryption count is split across domains, not shared.
- **Key rotation**: For high-volume applications (millions of records), rotate
  encryption keys before reaching 2³² encryptions per key_id. This resets the
  nonce counter space.
- **Monitor scale**: If your application encrypts >10⁶ fields per day, consider
  rotating keys quarterly or sooner.

#### Recommendation

For most applications, random nonces are safe. If you need deterministic nonce
generation (e.g., counter-based), you would need to implement a nonce tracking
layer — this library does not provide that.

### Blind Index Security

`BlindIndexField` uses HMAC-SHA256 with a key derived via HKDF from the master
key. This provides:

- **Deterministic hashing**: Same input always produces the same hash
- **Keyed hashing**: Without the key, hashes cannot be reverse-engineered
- **No rainbow table attacks**: Each key_id produces different hashes

#### Key Rotation Impact

Blind index hashes are tied to the encryption key. When you rotate keys:
- **Encrypted data**: Old ciphertext remains decryptable with old keys
- **Hash fields**: Old hashes become invalid for the new key

After key rotation, you must re-compute all hash fields:

```python
for obj in Model.objects.all():
    obj.hash_field = compute_hash(obj.encrypted_field)
    obj.save()
```

#### Collision Risk

HMAC-SHA256 produces a 256-bit output. Collision probability is negligible
(~2⁻¹²⁸ birthday bound) even at massive scale. No practical concern.

#### When to Use Blind Indexes

- **Use for**: Exact-match lookups (email, SSN, national ID)
- **Do not use for**: Range queries, partial matches, or ordering
- **Do not use for**: Low-entropy fields without `unique=True` — an attacker
  with database access could enumerate possible values and match hashes

## Best Practices

### Key Management

1. **Store keys securely**: Use environment variables or secrets management
2. **Never commit keys**: Keys must never enter version control
3. **Rotate keys**: Implement regular key rotation (90 days recommended)
4. **Keep old keys**: Maintain previous keys for decryption
5. **Audit key usage**: Log which key encrypts each value

```python
# Good: Environment variables
DATA_PROTECTION_KEYS = {
    'v1': os.environ.get('ENCRYPTION_KEY_V1'),
}

# Bad: Hardcoded key
DATA_PROTECTION_KEYS = {
    'v1': 'my-secret-key',  # Never do this
}
```

### Key Rotation

1. Add new key to DATA_PROTECTION_KEYS
2. Set DATA_PROTECTION_ACTIVE_KEY_ID to new key
3. Re-encrypt existing data:

```python
from django_field_encryption import rotate_keys, rotate_model_fields

rotate_keys(app_label='myapp')
rotate_model_fields(User, field_names=['ssn'])
```

4. Keep old key for decryption during transition

Dry run:

```python
rotate_keys(dry_run=True)
```

Management command:

```bash
python manage.py rotate_encryption_keys --dry-run
python manage.py rotate_encryption_keys
```

### Application Security

1. **HTTPS**: Always use TLS in transit
2. **Access control**: Restrict who can view decrypted data
3. **Logging**: Never log decrypted sensitive data
4. **Error handling**: Don't expose encrypted values in errors

## Limitations

### Data at Rest

The library does **not** encrypt the database at rest. It encrypts data in transit from application to database:
- Application → encrypted → Database
- Database → encrypted → Application → decrypted

The database stores encrypted values, not plaintext.

### Memory Security

- Decrypted data exists in memory
- Clear sensitive data when no longer needed
- Be aware of memory dumps and swap files

### Query Limitations

Encrypted fields cannot be used in queries:
- No filtering by encrypted values
- No searching within encrypted fields
- No ordering by encrypted fields

Use `BlindIndexField` for lookups:

```python
from django_field_encryption import EncryptedCharField, BlindIndexField, compute_hash

class UserProfile(models.Model):
    ssn = EncryptedCharField(max_length=20)
    ssn_hash = BlindIndexField('ssn', db_index=True)

# Lookup
UserProfile.objects.get(ssn_hash=compute_hash('29901012345678'))
```

**Bulk operations limitation**: `bulk_create` and `bulk_update` do not fire `pre_save` signals. Hashes must be computed manually:

```python
profiles = [UserProfile(email='a@x.com'), UserProfile(email='b@x.com')]
for p in profiles:
    p.email_hash = compute_hash(p.email)
UserProfile.objects.bulk_create(profiles)
```

### File Security

- Files are encrypted on disk
- Decrypted content exists in memory during access
- Original filenames may contain sensitive info - consider renaming

## Threat Model

### Protected Against

- Database compromise (values are encrypted)
- Database backup compromise
- Disk theft (files are encrypted)
- SQL injection reading from database

### Not Protected Against

- Application compromise (decrypted data in memory)
- Memory dumps
- Debugger attached to application
- Application logs containing sensitive data
- Network eavesdropping (use TLS)
- Insider threats with application access

## Compliance

### GDPR

- Encryption supports data minimization principles
- Keys can be rotated to limit exposure window
- Document encryption in privacy policy

### PCI-DSS

- Credit card data can be encrypted
- Use separate keys per environment
- Key rotation required

### HIPAA

- PHI can be encrypted
- Audit key access
- Document encryption in BAA

## Incident Response

If keys are compromised:

1. **Identify affected data**: Determine which fields/files use compromised key
2. **Contain**: Switch to new key immediately
3. **Assess**: Determine if data was accessed
4. **Remediate**: Re-encrypt with new key
5. **Document**: Report as required

```python
# Emergency key rotation
DATA_PROTECTION_KEYS = {
    'v1': 'OLD_COMPROMISED_KEY',  # Keep for now
    'v2': 'NEW_SECURE_KEY',
}
DATA_PROTECTION_ACTIVE_KEY_ID = 'v2'

# Re-encrypt all data
for obj in Model.objects.all():
    obj.secret = FieldEncryptor.rotate_value(obj.secret)
    obj.save()
```

## Testing Security

Use test keys in test environments:

```python
# settings_test.py
DATA_PROTECTION_KEYS = {
    'test': 'dGVzdGtleTZ0dzdzMna2V5Mm5rZnlqYW5rZnlqYW5rZnlqYW4=',  # Test key
}
DATA_PROTECTION_ACTIVE_KEY_ID = 'test'
```

Never use production keys in tests.

## Dependencies

The library depends on:

- `cryptography>=42.0.0` - For AES-GCM and HKDF
- `Django>=4.2` - For field/storage classes
- Python 3.9+ - For typing features

Keep these dependencies updated for security patches.