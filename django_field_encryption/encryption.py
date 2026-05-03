import base64
import hashlib
import logging
import os
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .conf import (
    NONCE_LENGTH,
    PREFIX_SEPARATOR,
    _get_active_key_id,
    _get_keys_config,
    _get_master_key,
)
from .exceptions import (
    DecryptionError,
    EncryptionError,
    EncryptionNotConfiguredError,
    InvalidKeyError,
)

logger = logging.getLogger(__name__)

FIELD_KEY_INFO_PREFIX = b'data-protection-field-'
FILE_KEY_INFO_PREFIX = b'data-protection-file-'


def _derive_aes_key(master_key: bytes, key_id: str, info_prefix: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hashlib.sha256(key_id.encode()).digest(),
        info=info_prefix + key_id.encode('utf-8'),
    )
    return hkdf.derive(master_key)


class FieldEncryptor:
    _key_cache: dict[str, AESGCM] = {}

    @classmethod
    def _get_aesgcm(
        cls, key_id: str, info_prefix: bytes = FIELD_KEY_INFO_PREFIX
    ) -> AESGCM:
        cache_key = f'{key_id}:{info_prefix.decode()}'
        if cache_key in cls._key_cache:
            return cls._key_cache[cache_key]
        master_key = _get_master_key(key_id)
        derived = _derive_aes_key(master_key, key_id, info_prefix)
        aesgcm = AESGCM(derived)
        cls._key_cache[cache_key] = aesgcm
        return aesgcm

    @classmethod
    def encrypt(cls, plaintext: str) -> str:
        if not plaintext:
            return plaintext
        key_id = _get_active_key_id()
        if not key_id:
            raise EncryptionNotConfiguredError(
                'No active encryption key configured. '
                'Set DATA_PROTECTION_ACTIVE_KEY_ID in settings.'
            )
        try:
            nonce = os.urandom(NONCE_LENGTH)
            aesgcm = cls._get_aesgcm(key_id)
            ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
            payload = nonce + ciphertext_with_tag
            encoded = base64.urlsafe_b64encode(payload).decode('ascii')
            return f'{key_id}{PREFIX_SEPARATOR}{encoded}'
        except InvalidKeyError:
            raise
        except Exception as e:
            logger.exception('Encryption failed for key_id=%s', key_id)
            raise EncryptionError(f'Encryption failed: {str(e)}') from e

    @classmethod
    def decrypt(cls, encrypted: str) -> str:
        if not encrypted or PREFIX_SEPARATOR not in encrypted:
            return encrypted
        try:
            key_id, encoded = encrypted.split(PREFIX_SEPARATOR, 1)
        except ValueError as e:
            raise DecryptionError(f'Invalid encrypted value format: {str(e)}') from e
        try:
            payload = base64.urlsafe_b64decode(encoded.encode('ascii'))
        except Exception as e:
            raise DecryptionError(
                'Invalid base64 encoding in ciphertext',
                key_id=key_id,
                original_exception=e,
            ) from e
        if len(payload) < NONCE_LENGTH:
            raise DecryptionError(
                f'Ciphertext too short: expected at least {NONCE_LENGTH} bytes, got {len(payload)}',
                key_id=key_id,
            )
        try:
            nonce = payload[:NONCE_LENGTH]
            ciphertext_with_tag = payload[NONCE_LENGTH:]
            aesgcm = cls._get_aesgcm(key_id)
            return aesgcm.decrypt(nonce, ciphertext_with_tag, None).decode('utf-8')
        except InvalidKeyError:
            raise
        except InvalidTag as e:
            raise DecryptionError(
                'Decryption failed: data may be tampered or wrong key',
                key_id=key_id,
                original_exception=e,
            ) from e
        except Exception as e:
            raise DecryptionError(
                f'Decryption failed: {str(e)}', key_id=key_id, original_exception=e
            ) from e

    @classmethod
    def can_decrypt(cls, encrypted: str) -> bool:
        if not encrypted or PREFIX_SEPARATOR not in encrypted:
            return False
        key_id = encrypted.split(PREFIX_SEPARATOR, 1)[0]
        return key_id in _get_keys_config()

    @classmethod
    def rotate_value(cls, encrypted: str) -> Optional[str]:
        if not encrypted or PREFIX_SEPARATOR not in encrypted:
            return None
        old_key_id = encrypted.split(PREFIX_SEPARATOR, 1)[0]
        active_key_id = _get_active_key_id()
        if old_key_id == active_key_id:
            return None
        plaintext = cls.decrypt(encrypted)
        return cls.encrypt(plaintext)

    @classmethod
    def clear_cache(cls):
        cls._key_cache.clear()


class FileEncryptor:
    _key_cache: dict[str, AESGCM] = {}

    FILE_MAGIC = b'ENC2'

    @classmethod
    def _get_aesgcm(cls, key_id: str) -> AESGCM:
        cache_key = f'{key_id}:file'
        if cache_key in cls._key_cache:
            return cls._key_cache[cache_key]
        master_key = _get_master_key(key_id)
        derived = _derive_aes_key(master_key, key_id, FILE_KEY_INFO_PREFIX)
        aesgcm = AESGCM(derived)
        cls._key_cache[cache_key] = aesgcm
        return aesgcm

    @classmethod
    def encrypt(cls, data: bytes) -> tuple[bytes, str]:
        if not data:
            return b'', ''
        key_id = _get_active_key_id()
        if not key_id:
            raise EncryptionNotConfiguredError(
                'No active encryption key configured. '
                'Set DATA_PROTECTION_ACTIVE_KEY_ID in settings.'
            )
        try:
            nonce = os.urandom(NONCE_LENGTH)
            aesgcm = cls._get_aesgcm(key_id)
            ciphertext_with_tag = aesgcm.encrypt(nonce, data, None)
            key_id_bytes = key_id.encode('utf-8')
            key_id_len = len(key_id_bytes)
            result = (
                cls.FILE_MAGIC
                + key_id_len.to_bytes(1, 'big')
                + key_id_bytes
                + nonce
                + ciphertext_with_tag
            )
            return result, key_id
        except InvalidKeyError:
            raise
        except Exception as e:
            logger.exception('File encryption failed for key_id=%s', key_id)
            raise EncryptionError(f'File encryption failed: {str(e)}') from e

    @classmethod
    def decrypt(cls, data: bytes) -> bytes:
        if not data or not data[:4] == cls.FILE_MAGIC:
            return data
        key_id: Optional[str] = None
        try:
            offset = 4
            key_id_len = data[offset]
            offset += 1
            key_id = data[offset : offset + key_id_len].decode('utf-8')
            offset += key_id_len
            nonce = data[offset : offset + NONCE_LENGTH]
            offset += NONCE_LENGTH
            ciphertext_with_tag = data[offset:]
        except Exception as e:
            raise DecryptionError(
                f'Failed to parse encrypted file header: {str(e)}',
                key_id=key_id,
                original_exception=e,
            ) from e

        if len(ciphertext_with_tag) < 16:
            raise DecryptionError(
                f'Ciphertext too short: expected at least 16 bytes, got {len(ciphertext_with_tag)}',
                key_id=key_id,
            )

        try:
            aesgcm = cls._get_aesgcm(key_id)
            return aesgcm.decrypt(nonce, ciphertext_with_tag, None)
        except InvalidKeyError:
            raise
        except InvalidTag as e:
            raise DecryptionError(
                'File decryption failed: data may be tampered or wrong key',
                key_id=key_id,
                original_exception=e,
            ) from e
        except Exception as e:
            raise DecryptionError(
                f'File decryption failed: {str(e)}',
                key_id=key_id,
                original_exception=e,
            ) from e

    @classmethod
    def is_encrypted(cls, data: bytes) -> bool:
        return len(data) >= 4 and data[:4] == cls.FILE_MAGIC

    @classmethod
    def clear_cache(cls):
        cls._key_cache.clear()


def generate_master_key() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).decode('ascii')
