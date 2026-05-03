import base64

from django.test import TestCase, override_settings

TEST_MASTER_KEY = base64.urlsafe_b64encode(b'\x01' * 32).decode()
TEST_MASTER_KEY_V2 = base64.urlsafe_b64encode(b'\x02' * 32).decode()

ENCRYPTION_SETTINGS = {
    'DATA_PROTECTION_KEYS': {'v1': TEST_MASTER_KEY},
    'DATA_PROTECTION_ACTIVE_KEY_ID': 'v1',
}


@override_settings(**ENCRYPTION_SETTINGS)
class TestFieldEncryptor(TestCase):
    def setUp(self):
        from django_field_encryption import FieldEncryptor

        self.encryptor = FieldEncryptor
        self.encryptor.clear_cache()

    def test_encrypt_decrypt_roundtrip(self):
        plaintext = '29901012345678'
        encrypted = self.encryptor.encrypt(plaintext)
        self.assertNotEqual(encrypted, plaintext)
        self.assertTrue(encrypted.startswith('v1:'))
        decrypted = self.encryptor.decrypt(encrypted)
        self.assertEqual(decrypted, plaintext)

    def test_encrypt_empty_string(self):
        self.assertEqual(self.encryptor.encrypt(''), '')

    def test_decrypt_empty_string(self):
        self.assertEqual(self.encryptor.decrypt(''), '')

    def test_decrypt_plaintext_passthrough(self):
        plaintext = 'not-encrypted'
        self.assertEqual(self.encryptor.decrypt(plaintext), plaintext)

    def test_different_ciphertexts_for_same_plaintext(self):
        plaintext = '29901012345678'
        encrypted1 = self.encryptor.encrypt(plaintext)
        encrypted2 = self.encryptor.encrypt(plaintext)
        self.assertNotEqual(encrypted1, encrypted2)
        self.assertEqual(self.encryptor.decrypt(encrypted1), plaintext)
        self.assertEqual(self.encryptor.decrypt(encrypted2), plaintext)

    def test_key_id_prefixed_in_ciphertext(self):
        encrypted = self.encryptor.encrypt('test')
        key_id = encrypted.split(':')[0]
        self.assertEqual(key_id, 'v1')

    def test_can_decrypt_valid_key(self):
        encrypted = self.encryptor.encrypt('test')
        self.assertTrue(self.encryptor.can_decrypt(encrypted))

    def test_can_decrypt_unknown_key(self):
        self.assertFalse(self.encryptor.can_decrypt('v99:somegarbage'))

    def test_unicode_roundtrip(self):
        plaintext = 'مرحبا العالم — هِشَام'
        encrypted = self.encryptor.encrypt(plaintext)
        self.assertEqual(self.encryptor.decrypt(encrypted), plaintext)

    def test_long_string_roundtrip(self):
        plaintext = 'A' * 10000
        encrypted = self.encryptor.encrypt(plaintext)
        self.assertEqual(self.encryptor.decrypt(encrypted), plaintext)


@override_settings(
    DATA_PROTECTION_KEYS={'v1': TEST_MASTER_KEY, 'v2': TEST_MASTER_KEY_V2},
    DATA_PROTECTION_ACTIVE_KEY_ID='v2',
)
class TestFieldEncryptorKeyRotation(TestCase):
    def setUp(self):
        from django_field_encryption import FieldEncryptor

        self.encryptor = FieldEncryptor
        self.encryptor.clear_cache()

    def test_decrypt_with_old_key(self):
        v1_settings = {
            'DATA_PROTECTION_KEYS': {'v1': TEST_MASTER_KEY},
            'DATA_PROTECTION_ACTIVE_KEY_ID': 'v1',
        }
        with override_settings(**v1_settings):
            self.encryptor.clear_cache()
            encrypted_v1 = self.encryptor.encrypt('secret_data')

        self.encryptor.clear_cache()
        decrypted = self.encryptor.decrypt(encrypted_v1)
        self.assertEqual(decrypted, 'secret_data')

    def test_rotate_value_re_encrypts_with_active_key(self):
        v1_settings = {
            'DATA_PROTECTION_KEYS': {'v1': TEST_MASTER_KEY},
            'DATA_PROTECTION_ACTIVE_KEY_ID': 'v1',
        }
        with override_settings(**v1_settings):
            self.encryptor.clear_cache()
            encrypted_v1 = self.encryptor.encrypt('rotation_test')

        self.encryptor.clear_cache()
        rotated = self.encryptor.rotate_value(encrypted_v1)
        self.assertIsNotNone(rotated)
        self.assertTrue(rotated and rotated.startswith('v2:'))
        self.assertEqual(self.encryptor.decrypt(rotated), 'rotation_test')  # type: ignore[arg-type]

    def test_rotate_value_no_change_if_same_key(self):
        encrypted = self.encryptor.encrypt('same_key_test')
        rotated = self.encryptor.rotate_value(encrypted)
        self.assertIsNone(rotated)

    def test_rotate_value_empty_string(self):
        self.assertIsNone(self.encryptor.rotate_value(''))

    def test_rotate_value_non_encrypted_string(self):
        self.assertIsNone(self.encryptor.rotate_value('plain text'))


@override_settings(**ENCRYPTION_SETTINGS)
class TestComputeHash(TestCase):
    def test_hash_deterministic(self):
        from django_field_encryption import compute_hash

        h1 = compute_hash('29901012345678')
        h2 = compute_hash('29901012345678')
        self.assertEqual(h1, h2)

    def test_hash_different_inputs(self):
        from django_field_encryption import compute_hash

        h1 = compute_hash('29901012345678')
        h2 = compute_hash('29901012345679')
        self.assertNotEqual(h1, h2)

    def test_hash_length(self):
        from django_field_encryption import compute_hash

        h = compute_hash('test')
        self.assertEqual(len(h), 64)


@override_settings(**ENCRYPTION_SETTINGS)
class TestTamperDetection(TestCase):
    def setUp(self):
        from django_field_encryption import FieldEncryptor

        self.encryptor = FieldEncryptor
        self.encryptor.clear_cache()

    def test_tampered_ciphertext_fails(self):
        encrypted = self.encryptor.encrypt('secret')
        key_id, encoded = encrypted.split(':', 1)
        payload = base64.urlsafe_b64decode(encoded.encode())
        tampered = payload[:-1] + bytes([(payload[-1] ^ 0xFF)])
        tampered_encoded = base64.urlsafe_b64encode(tampered).decode()
        tampered_encrypted = f'{key_id}:{tampered_encoded}'

        from django_field_encryption.exceptions import DecryptionError

        with self.assertRaises(DecryptionError):
            self.encryptor.decrypt(tampered_encrypted)


@override_settings(**ENCRYPTION_SETTINGS)
class TestEncryptedCharField(TestCase):
    def test_encrypted_char_field_roundtrip(self):
        from django_field_encryption import EncryptedCharField

        field = EncryptedCharField()
        original = '29901012345678'
        prep_value = field.get_prep_value(original)
        self.assertNotEqual(prep_value, original)
        self.assertTrue(prep_value.startswith('v1:'))
        python_value = field.to_python(prep_value)
        self.assertEqual(python_value, original)

    def test_encrypted_char_field_empty(self):
        from django_field_encryption import EncryptedCharField

        field = EncryptedCharField()
        self.assertIsNone(field.get_prep_value(None))
        self.assertEqual(field.get_prep_value(''), '')

    def test_encrypted_text_field_roundtrip(self):
        from django_field_encryption import EncryptedTextField

        field = EncryptedTextField()
        original = 'Long text with special chars: مرحبا'
        prep_value = field.get_prep_value(original)
        self.assertNotEqual(prep_value, original)
        python_value = field.to_python(prep_value)
        self.assertEqual(python_value, original)

    def test_encrypted_json_field_roundtrip(self):
        import json

        from django_field_encryption import EncryptedJSONField

        field = EncryptedJSONField()
        original = {'weights': {'EGX100': 0.42, 'XAU_EGP': 0.23}}
        prep_value = field.get_prep_value(original)
        self.assertNotEqual(prep_value, json.dumps(original))
        python_value = field.to_python(prep_value)
        self.assertEqual(python_value, original)


@override_settings(**ENCRYPTION_SETTINGS)
class TestNationalIdModel(TestCase):
    def test_national_id_hash_auto_computed(self):
        from django_field_encryption import compute_hash

        hash_val = compute_hash('29901012345678')
        self.assertEqual(len(hash_val), 64)
        self.assertIsInstance(hash_val, str)


@override_settings(**ENCRYPTION_SETTINGS)
class TestKeyDerivationIsolation(TestCase):
    def test_field_and_file_keys_are_different(self):
        from django_field_encryption.conf import (
            _get_master_key,
        )
        from django_field_encryption.encryption import (
            FIELD_KEY_INFO_PREFIX,
            FILE_KEY_INFO_PREFIX,
            _derive_aes_key,
        )

        master_key = _get_master_key('v1')
        field_key = _derive_aes_key(master_key, 'v1', FIELD_KEY_INFO_PREFIX)
        file_key = _derive_aes_key(master_key, 'v1', FILE_KEY_INFO_PREFIX)
        self.assertNotEqual(field_key, file_key)

    def test_different_key_ids_produce_different_keys(self):
        from django_field_encryption.conf import (
            _get_master_key,
        )
        from django_field_encryption.encryption import (
            FIELD_KEY_INFO_PREFIX,
            _derive_aes_key,
        )

        v2_settings = {
            'DATA_PROTECTION_KEYS': {'v1': TEST_MASTER_KEY, 'v2': TEST_MASTER_KEY_V2},
            'DATA_PROTECTION_ACTIVE_KEY_ID': 'v1',
        }
        with override_settings(**v2_settings):
            from django_field_encryption import FieldEncryptor

            FieldEncryptor.clear_cache()
            key1 = _derive_aes_key(_get_master_key('v1'), 'v1', FIELD_KEY_INFO_PREFIX)
            key2 = _derive_aes_key(_get_master_key('v2'), 'v2', FIELD_KEY_INFO_PREFIX)
            self.assertNotEqual(key1, key2)


class TestGenerateMasterKey(TestCase):
    def test_generates_valid_base64_key(self):
        from django_field_encryption import generate_master_key

        key = generate_master_key()
        decoded = base64.urlsafe_b64decode(key)
        self.assertEqual(len(decoded), 32)

    def test_generates_unique_keys(self):
        from django_field_encryption import generate_master_key

        key1 = generate_master_key()
        key2 = generate_master_key()
        self.assertNotEqual(key1, key2)


class TestErrorHandling(TestCase):
    def test_encrypt_without_config_raises_error(self):
        from django_field_encryption import FieldEncryptor
        from django_field_encryption.exceptions import EncryptionNotConfiguredError

        FieldEncryptor.clear_cache()
        no_keys_settings = {}
        with override_settings(**no_keys_settings):
            FieldEncryptor.clear_cache()
            with self.assertRaises(EncryptionNotConfiguredError):
                FieldEncryptor.encrypt('test')

    def test_encrypt_with_unknown_key_raises_error(self):
        from django_field_encryption import FieldEncryptor
        from django_field_encryption.exceptions import InvalidKeyError

        FieldEncryptor.clear_cache()
        bad_key_settings = {
            'DATA_PROTECTION_KEYS': {'v1': TEST_MASTER_KEY},
            'DATA_PROTECTION_ACTIVE_KEY_ID': 'nonexistent',
        }
        with override_settings(**bad_key_settings):
            FieldEncryptor.clear_cache()
            with self.assertRaises(InvalidKeyError):
                FieldEncryptor.encrypt('test')

    def test_decrypt_invalid_format_raises_error(self):
        from django_field_encryption import FieldEncryptor
        from django_field_encryption.exceptions import DecryptionError

        FieldEncryptor.clear_cache()
        with override_settings(**ENCRYPTION_SETTINGS):
            FieldEncryptor.clear_cache()
            with self.assertRaises(DecryptionError):
                FieldEncryptor.decrypt('invalid:not-base64!')

    def test_decrypt_unknown_key_id_raises_error(self):
        from django_field_encryption import FieldEncryptor
        from django_field_encryption.exceptions import InvalidKeyError

        FieldEncryptor.clear_cache()
        with override_settings(**ENCRYPTION_SETTINGS):
            FieldEncryptor.clear_cache()
            valid_length_ciphertext = base64.urlsafe_b64encode(b'0' * 28).decode()
            with self.assertRaises(InvalidKeyError):
                FieldEncryptor.decrypt(f'v99:{valid_length_ciphertext}')

    def test_decrypt_tampered_data_raises_error(self):
        from django_field_encryption import FieldEncryptor
        from django_field_encryption.exceptions import DecryptionError

        FieldEncryptor.clear_cache()
        with override_settings(**ENCRYPTION_SETTINGS):
            FieldEncryptor.clear_cache()
            encrypted = FieldEncryptor.encrypt('secret')
            tampered = encrypted[:-2] + 'XX'
            with self.assertRaises(DecryptionError):
                FieldEncryptor.decrypt(tampered)

    def test_decrypt_error_contains_key_id(self):
        from django_field_encryption import FieldEncryptor
        from django_field_encryption.exceptions import DecryptionError

        FieldEncryptor.clear_cache()
        with override_settings(**ENCRYPTION_SETTINGS):
            FieldEncryptor.clear_cache()
            encrypted = FieldEncryptor.encrypt('secret')
            tampered = encrypted[:-2] + 'XX'
            try:
                FieldEncryptor.decrypt(tampered)
            except DecryptionError as e:
                self.assertEqual(e.key_id, 'v1')
                self.assertIsNotNone(e.original_exception)

    def test_invalid_key_format_raises_error(self):
        from django_field_encryption import FieldEncryptor
        from django_field_encryption.exceptions import InvalidKeyError

        FieldEncryptor.clear_cache()
        bad_key_settings = {
            'DATA_PROTECTION_KEYS': {'v1': 'not-a-valid-key'},
            'DATA_PROTECTION_ACTIVE_KEY_ID': 'v1',
        }
        with override_settings(**bad_key_settings):
            FieldEncryptor.clear_cache()
            with self.assertRaises(InvalidKeyError):
                FieldEncryptor.encrypt('test')

    def test_wrong_key_length_raises_error(self):
        from django_field_encryption import FieldEncryptor
        from django_field_encryption.exceptions import InvalidKeyError

        FieldEncryptor.clear_cache()
        bad_key_settings = {
            'DATA_PROTECTION_KEYS': {'v1': 'this-is-5-bytes!!'},
            'DATA_PROTECTION_ACTIVE_KEY_ID': 'v1',
        }
        with override_settings(**bad_key_settings):
            FieldEncryptor.clear_cache()
            with self.assertRaises(InvalidKeyError) as ctx:
                FieldEncryptor.encrypt('test')
            self.assertEqual(ctx.exception.key_id, 'v1')
            self.assertEqual(ctx.exception.key_length, 17)


class TestFieldStrictMode(TestCase):
    def test_encrypted_char_field_strict_raises_on_encrypt_error(self):
        from django_field_encryption import EncryptedCharField, FieldEncryptor
        from django_field_encryption.exceptions import EncryptionNotConfiguredError

        FieldEncryptor.clear_cache()
        no_keys_settings = {}
        with override_settings(**no_keys_settings):
            FieldEncryptor.clear_cache()
            field = EncryptedCharField(strict=True)
            with self.assertRaises(EncryptionNotConfiguredError):
                field.get_prep_value('test')

    def test_encrypted_char_field_non_strict_passes_through(self):
        from django_field_encryption import EncryptedCharField, FieldEncryptor

        FieldEncryptor.clear_cache()
        with override_settings(**ENCRYPTION_SETTINGS):
            FieldEncryptor.clear_cache()
            field = EncryptedCharField(strict=False)
            result = field.get_prep_value('test')
            self.assertTrue(result.startswith('v1:'))

    def test_encrypted_char_field_non_strict_handles_encrypt_failure(self):
        from django_field_encryption import EncryptedCharField, FieldEncryptor

        FieldEncryptor.clear_cache()
        no_keys_settings = {}
        with override_settings(**no_keys_settings):
            FieldEncryptor.clear_cache()
            field = EncryptedCharField(strict=False)
            result = field.get_prep_value('test')
            self.assertEqual(result, 'test')

    def test_encrypted_text_field_strict_raises_on_decrypt_error(self):
        from django_field_encryption import EncryptedTextField, FieldEncryptor
        from django_field_encryption.exceptions import DecryptionError

        FieldEncryptor.clear_cache()
        with override_settings(**ENCRYPTION_SETTINGS):
            FieldEncryptor.clear_cache()
            field = EncryptedTextField(strict=True)
            tampered = 'v1:invalidbase64'
            with self.assertRaises(DecryptionError):
                field.to_python(tampered)

    def test_encrypted_text_field_non_strict_passes_through(self):
        from django_field_encryption import EncryptedTextField, FieldEncryptor

        FieldEncryptor.clear_cache()
        with override_settings(**ENCRYPTION_SETTINGS):
            FieldEncryptor.clear_cache()
            field = EncryptedTextField(strict=False)
            tampered = 'v1:invalidbase64'
            result = field.to_python(tampered)
            self.assertEqual(result, tampered)
