import base64
import os

from django.test import TestCase, override_settings

TEST_MASTER_KEY = base64.urlsafe_b64encode(b'\x01' * 32).decode()

ENCRYPTION_SETTINGS = {
    'DATA_PROTECTION_KEYS': {'v1': TEST_MASTER_KEY},
    'DATA_PROTECTION_ACTIVE_KEY_ID': 'v1',
}


@override_settings(**ENCRYPTION_SETTINGS)
class TestFileEncryptor(TestCase):
    def setUp(self):
        from django_field_encryption import FileEncryptor

        self.encryptor = FileEncryptor
        self.encryptor.clear_cache()

    def test_encrypt_decrypt_roundtrip(self):
        plaintext = b'This is a KYC document content'
        encrypted, key_id = self.encryptor.encrypt(plaintext)
        self.assertEqual(key_id, 'v1')
        self.assertTrue(encrypted.startswith(b'ENC2'))
        decrypted = self.encryptor.decrypt(encrypted)
        self.assertEqual(decrypted, plaintext)

    def test_encrypt_empty_bytes_produces_ciphertext(self):
        encrypted, key_id = self.encryptor.encrypt(b'')
        self.assertEqual(key_id, 'v1')
        self.assertTrue(encrypted.startswith(b'ENC2'))
        decrypted = self.encryptor.decrypt(encrypted)
        self.assertEqual(decrypted, b'')

    def test_is_encrypted_true(self):
        plaintext = b'test'
        encrypted, _ = self.encryptor.encrypt(plaintext)
        self.assertTrue(self.encryptor.is_encrypted(encrypted))

    def test_is_encrypted_false(self):
        self.assertFalse(self.encryptor.is_encrypted(b'plain'))
        self.assertFalse(self.encryptor.is_encrypted(b''))

    def test_decrypt_non_encrypted_passthrough(self):
        plaintext = b'not encrypted content'
        self.assertEqual(self.encryptor.decrypt(plaintext), plaintext)

    def test_large_file_roundtrip(self):
        plaintext = os.urandom(1024 * 1024)
        encrypted, _ = self.encryptor.encrypt(plaintext)
        decrypted = self.encryptor.decrypt(encrypted)
        self.assertEqual(decrypted, plaintext)


@override_settings(**ENCRYPTION_SETTINGS)
class TestEncryptedFileStorage(TestCase):
    def test_storage_encrypt_decrypt_roundtrip(self):
        from django.core.files.base import ContentFile

        from django_field_encryption import encrypted_file_storage

        original_content = b'test document content'
        content = ContentFile(original_content, name='test_id.pdf')
        saved_name = encrypted_file_storage._save('files/test/test_id.pdf', content)

        with encrypted_file_storage._open(saved_name) as f:
            retrieved = f.read()
        self.assertEqual(retrieved, original_content)

        encrypted_file_storage.delete(saved_name)

    def test_storage_empty_file_roundtrip(self):
        from django.core.files.base import ContentFile

        from django_field_encryption import encrypted_file_storage

        original_content = b''
        content = ContentFile(original_content, name='empty.txt')
        saved_name = encrypted_file_storage._save('files/test/empty.txt', content)

        with encrypted_file_storage._open(saved_name) as f:
            retrieved = f.read()
        self.assertEqual(retrieved, original_content)

        encrypted_file_storage.delete(saved_name)


@override_settings(**ENCRYPTION_SETTINGS)
class TestBaseEncryptedStorage(TestCase):
    def test_base_storage_with_custom_underlying(self):
        from django.core.files.storage import FileSystemStorage

        from django_field_encryption.storage import BaseEncryptedStorage

        underlying = FileSystemStorage(location='/tmp/test_encrypted_storage')
        storage = BaseEncryptedStorage(underlying_storage=underlying)

        from django.core.files.base import ContentFile

        original = b'base storage test'
        content = ContentFile(original, name='test.bin')
        saved = storage._save('test.bin', content)

        with storage._open(saved) as f:
            retrieved = f.read()
        self.assertEqual(retrieved, original)

        storage.delete(saved)


@override_settings(**ENCRYPTION_SETTINGS)
class TestFileTamperDetection(TestCase):
    def setUp(self):
        from django_field_encryption import FileEncryptor

        self.encryptor = FileEncryptor
        self.encryptor.clear_cache()

    def test_tampered_file_fails(self):
        encrypted, _ = self.encryptor.encrypt(b'test data')
        tampered = bytearray(encrypted)
        tampered[-1] ^= 0xFF
        tampered = bytes(tampered)

        from django_field_encryption.exceptions import DecryptionError

        with self.assertRaises(DecryptionError):
            self.encryptor.decrypt(tampered)


class TestFileErrorHandling(TestCase):
    def test_file_encrypt_without_config_raises_error(self):
        from django_field_encryption import FileEncryptor
        from django_field_encryption.exceptions import EncryptionNotConfiguredError

        FileEncryptor.clear_cache()
        no_keys_settings = {}
        with override_settings(**no_keys_settings):
            FileEncryptor.clear_cache()
            with self.assertRaises(EncryptionNotConfiguredError):
                FileEncryptor.encrypt(b'test')
