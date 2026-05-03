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

    def test_encrypt_empty_bytes(self):
        encrypted, key_id = self.encryptor.encrypt(b'')
        decrypted = self.encryptor.decrypt(encrypted)
        self.assertEqual(decrypted, b'')

    def test_large_file_roundtrip(self):
        plaintext = os.urandom(1024 * 1024)  # 1MB
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
