import base64

from django.core.exceptions import ValidationError
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

    def test_encrypt_empty_string_produces_ciphertext(self):
        encrypted = self.encryptor.encrypt('')
        self.assertNotEqual(encrypted, '')
        self.assertTrue(encrypted.startswith('v1:'))
        decrypted = self.encryptor.decrypt(encrypted)
        self.assertEqual(decrypted, '')

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

    def test_is_encrypted_valid_ciphertext(self):
        encrypted = self.encryptor.encrypt('secret')
        self.assertTrue(self.encryptor.is_encrypted(encrypted))

    def test_is_encrypted_plaintext(self):
        self.assertFalse(self.encryptor.is_encrypted('hello world'))

    def test_is_encrypted_empty_string(self):
        self.assertFalse(self.encryptor.is_encrypted(''))

    def test_is_encrypted_none(self):
        self.assertFalse(self.encryptor.is_encrypted(None))

    def test_is_encrypted_malformed_base64(self):
        self.assertFalse(self.encryptor.is_encrypted('v1:!!!invalid@@@'))

    def test_is_encrypted_unknown_key_id(self):
        self.assertFalse(self.encryptor.is_encrypted('v99:YWJjZGVmZ2hpamtsbW5vcA=='))

    def test_is_encrypted_short_payload(self):
        import base64

        short_payload = base64.urlsafe_b64encode(b'short').decode()
        self.assertFalse(self.encryptor.is_encrypted(f'v1:{short_payload}'))

    def test_encrypted_field_is_encrypted_method(self):
        from django_field_encryption import EncryptedCharField

        field = EncryptedCharField()
        encrypted = field._encrypt_value('test')
        self.assertTrue(field.is_encrypted(encrypted))
        self.assertFalse(field.is_encrypted('plain text'))

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
        assert rotated is not None
        self.assertTrue(rotated.startswith('v2:'))
        self.assertEqual(self.encryptor.decrypt(rotated), 'rotation_test')

    def test_rotate_value_no_change_if_same_key(self):
        encrypted = self.encryptor.encrypt('same_key_test')
        rotated = self.encryptor.rotate_value(encrypted)
        self.assertEqual(rotated, encrypted)

    def test_rotate_value_empty_string(self):
        self.assertEqual(self.encryptor.rotate_value(''), '')

    def test_rotate_value_non_encrypted_string(self):
        self.assertEqual(self.encryptor.rotate_value('plain text'), 'plain text')


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

    def test_encrypted_char_field_empty_string_encrypted(self):
        from django_field_encryption import EncryptedCharField

        field = EncryptedCharField()
        prep_value = field.get_prep_value('')
        self.assertNotEqual(prep_value, '')
        self.assertTrue(prep_value.startswith('v1:'))
        python_value = field.to_python(prep_value)
        self.assertEqual(python_value, '')

    def test_encrypted_char_field_none(self):
        from django_field_encryption import EncryptedCharField

        field = EncryptedCharField()
        self.assertIsNone(field.get_prep_value(None))

    def test_encrypted_char_field_max_length_validation(self):
        from django_field_encryption import EncryptedCharField

        field = EncryptedCharField(max_length=5)
        field.run_validators('12345')
        with self.assertRaises(ValidationError):
            field.run_validators('123456')

    def test_encrypted_char_field_max_length_on_ciphertext(self):
        from django_field_encryption import EncryptedCharField, FieldEncryptor

        field = EncryptedCharField(max_length=5)
        ciphertext = FieldEncryptor.encrypt('ab')
        field.run_validators(ciphertext)
        long_ciphertext = FieldEncryptor.encrypt('abcdef')
        with self.assertRaises(ValidationError):
            field.run_validators(long_ciphertext)

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

    def test_encrypted_json_field_none(self):
        from django_field_encryption import EncryptedJSONField

        field = EncryptedJSONField()
        self.assertIsNone(field.get_prep_value(None))

    def test_encrypted_json_field_empty_dict(self):
        from django_field_encryption import EncryptedJSONField

        field = EncryptedJSONField()
        prep_value = field.get_prep_value({})
        self.assertTrue(prep_value.startswith('v1:'))
        python_value = field.to_python(prep_value)
        self.assertEqual(python_value, {})


@override_settings(**ENCRYPTION_SETTINGS)
class TestEncryptedTypedFields(TestCase):
    def test_integer_field_roundtrip(self):
        from django_field_encryption import EncryptedIntegerField

        field = EncryptedIntegerField()
        prep_value = field.get_prep_value(42)
        self.assertNotEqual(prep_value, '42')
        self.assertTrue(prep_value.startswith('v1:'))
        python_value = field.to_python(prep_value)
        self.assertEqual(python_value, 42)
        self.assertIsInstance(python_value, int)

    def test_integer_field_from_db_value(self):
        from django_field_encryption import EncryptedIntegerField

        field = EncryptedIntegerField()
        prep_value = field.get_prep_value(42)
        db_value = field.from_db_value(prep_value, None, None)
        self.assertEqual(db_value, 42)
        self.assertIsInstance(db_value, int)

    def test_integer_field_none(self):
        from django_field_encryption import EncryptedIntegerField

        field = EncryptedIntegerField()
        self.assertIsNone(field.get_prep_value(None))
        self.assertIsNone(field.from_db_value(None, None, None))

    def test_datetime_field_roundtrip(self):
        from datetime import datetime

        from django_field_encryption import EncryptedDateTimeField

        field = EncryptedDateTimeField()
        dt = datetime(2024, 1, 15, 10, 30, 0)
        prep_value = field.get_prep_value(dt)
        self.assertNotEqual(prep_value, str(dt))
        self.assertTrue(prep_value.startswith('v1:'))
        python_value = field.to_python(prep_value)
        self.assertEqual(python_value, dt)
        self.assertIsInstance(python_value, datetime)

    def test_datetime_field_from_db_value(self):
        from datetime import datetime

        from django_field_encryption import EncryptedDateTimeField

        field = EncryptedDateTimeField()
        dt = datetime(2024, 1, 15, 10, 30, 0)
        prep_value = field.get_prep_value(dt)
        db_value = field.from_db_value(prep_value, None, None)
        self.assertEqual(db_value, dt)
        self.assertIsInstance(db_value, datetime)

    def test_datetime_field_none(self):
        from django_field_encryption import EncryptedDateTimeField

        field = EncryptedDateTimeField()
        self.assertIsNone(field.get_prep_value(None))
        self.assertIsNone(field.from_db_value(None, None, None))

    def test_date_field_roundtrip(self):
        from datetime import date

        from django_field_encryption import EncryptedDateField

        field = EncryptedDateField()
        d = date(2024, 1, 15)
        prep_value = field.get_prep_value(d)
        self.assertNotEqual(prep_value, str(d))
        self.assertTrue(prep_value.startswith('v1:'))
        python_value = field.to_python(prep_value)
        self.assertEqual(python_value, d)
        self.assertIsInstance(python_value, date)

    def test_date_field_from_db_value(self):
        from datetime import date

        from django_field_encryption import EncryptedDateField

        field = EncryptedDateField()
        d = date(2024, 1, 15)
        prep_value = field.get_prep_value(d)
        db_value = field.from_db_value(prep_value, None, None)
        self.assertEqual(db_value, d)
        self.assertIsInstance(db_value, date)

    def test_date_field_none(self):
        from django_field_encryption import EncryptedDateField

        field = EncryptedDateField()
        self.assertIsNone(field.get_prep_value(None))
        self.assertIsNone(field.from_db_value(None, None, None))


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
        from django_field_encryption.exceptions import ConfigurationError

        FieldEncryptor.clear_cache()
        no_keys_settings = {}
        with override_settings(**no_keys_settings):
            FieldEncryptor.clear_cache()
            with self.assertRaises(ConfigurationError):
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
        from django_field_encryption.exceptions import ConfigurationError

        FieldEncryptor.clear_cache()
        no_keys_settings = {}
        with override_settings(**no_keys_settings):
            FieldEncryptor.clear_cache()
            field = EncryptedCharField(strict=True)
            with self.assertRaises(ConfigurationError):
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


class TestEncryptedFieldInitGuards(TestCase):
    def test_primary_key_raises_improperly_configured(self):
        from django.core.exceptions import ImproperlyConfigured

        from django_field_encryption import EncryptedCharField

        with self.assertRaises(ImproperlyConfigured):
            EncryptedCharField(primary_key=True)

    def test_unique_raises_improperly_configured(self):
        from django.core.exceptions import ImproperlyConfigured

        from django_field_encryption import EncryptedCharField

        with self.assertRaises(ImproperlyConfigured):
            EncryptedCharField(unique=True)

    def test_db_index_raises_improperly_configured(self):
        from django.core.exceptions import ImproperlyConfigured

        from django_field_encryption import EncryptedCharField

        with self.assertRaises(ImproperlyConfigured):
            EncryptedCharField(db_index=True)

    def test_primary_key_false_is_allowed(self):
        from django_field_encryption import EncryptedCharField

        field = EncryptedCharField(primary_key=False)
        self.assertFalse(field.primary_key)

    def test_unique_false_is_allowed(self):
        from django_field_encryption import EncryptedCharField

        field = EncryptedCharField(unique=False)
        self.assertFalse(field.unique)

    def test_db_index_false_is_allowed(self):
        from django_field_encryption import EncryptedCharField

        field = EncryptedCharField(db_index=False)
        self.assertFalse(field.db_index)

    def test_text_field_unique_raises_improperly_configured(self):
        from django.core.exceptions import ImproperlyConfigured

        from django_field_encryption import EncryptedTextField

        with self.assertRaises(ImproperlyConfigured):
            EncryptedTextField(unique=True)

    def test_integer_field_db_index_raises_improperly_configured(self):
        from django.core.exceptions import ImproperlyConfigured

        from django_field_encryption import EncryptedIntegerField

        with self.assertRaises(ImproperlyConfigured):
            EncryptedIntegerField(db_index=True)

    def test_base_encrypted_field_primary_key_raises(self):
        from django.core.exceptions import ImproperlyConfigured

        from django_field_encryption import EncryptedFieldMixin

        with self.assertRaises(ImproperlyConfigured):
            EncryptedFieldMixin(primary_key=True)


class TestEncryptedFieldLookupBlocking(TestCase):
    def test_exact_lookup_raises_field_error(self):
        from django.core.exceptions import FieldError

        from django_field_encryption import EncryptedCharField

        field = EncryptedCharField()
        with self.assertRaises(FieldError):
            field.get_lookup('exact')

    def test_exact_lookup_error_mentions_field_name(self):
        from django.core.exceptions import FieldError

        from django_field_encryption import EncryptedCharField

        field = EncryptedCharField()
        try:
            field.get_lookup('exact')
        except FieldError as e:
            self.assertIn('EncryptedCharField', str(e))
            self.assertIn('exact', str(e))

    def test_contains_lookup_raises_field_error(self):
        from django.core.exceptions import FieldError

        from django_field_encryption import EncryptedCharField

        field = EncryptedCharField()
        with self.assertRaises(FieldError):
            field.get_lookup('contains')

    def test_icontains_lookup_raises_field_error(self):
        from django.core.exceptions import FieldError

        from django_field_encryption import EncryptedCharField

        field = EncryptedCharField()
        with self.assertRaises(FieldError):
            field.get_lookup('icontains')

    def test_gt_lookup_raises_field_error(self):
        from django.core.exceptions import FieldError

        from django_field_encryption import EncryptedCharField

        field = EncryptedCharField()
        with self.assertRaises(FieldError):
            field.get_lookup('gt')

    def test_isnull_lookup_is_allowed(self):
        from django.db.models.lookups import IsNull

        from django_field_encryption import EncryptedCharField

        field = EncryptedCharField()
        lookup = field.get_lookup('isnull')
        self.assertEqual(lookup, IsNull)

    def test_text_field_exact_lookup_raises_field_error(self):
        from django.core.exceptions import FieldError

        from django_field_encryption import EncryptedTextField

        field = EncryptedTextField()
        with self.assertRaises(FieldError):
            field.get_lookup('exact')

    def test_integer_field_exact_lookup_raises_field_error(self):
        from django.core.exceptions import FieldError

        from django_field_encryption import EncryptedIntegerField

        field = EncryptedIntegerField()
        with self.assertRaises(FieldError):
            field.get_lookup('exact')

    def test_error_message_mentions_blind_index(self):
        from django.core.exceptions import FieldError

        from django_field_encryption import EncryptedCharField

        field = EncryptedCharField()
        try:
            field.get_lookup('exact')
        except FieldError as e:
            self.assertIn('BlindIndexField', str(e))


@override_settings(**ENCRYPTION_SETTINGS)
class TestComputeHash(TestCase):
    def setUp(self):
        from django_field_encryption import FieldEncryptor

        FieldEncryptor.clear_cache()

    def test_compute_hash_returns_hex_string(self):
        from django_field_encryption import compute_hash

        result = compute_hash('test_value')
        self.assertEqual(len(result), 64)
        self.assertTrue(all(c in '0123456789abcdef' for c in result))

    def test_compute_hash_is_deterministic(self):
        from django_field_encryption import compute_hash

        result1 = compute_hash('same_value')
        result2 = compute_hash('same_value')
        self.assertEqual(result1, result2)

    def test_compute_hash_differs_for_different_values(self):
        from django_field_encryption import compute_hash

        result1 = compute_hash('value1')
        result2 = compute_hash('value2')
        self.assertNotEqual(result1, result2)

    def test_compute_hash_is_keyed_not_raw_sha256(self):
        import hashlib

        from django_field_encryption import compute_hash

        result = compute_hash('test_value')
        raw_sha256 = hashlib.sha256(b'test_value').hexdigest()
        self.assertNotEqual(result, raw_sha256)

    def test_compute_hash_without_config_raises_error(self):
        from django_field_encryption import FieldEncryptor, compute_hash
        from django_field_encryption.exceptions import ConfigurationError

        FieldEncryptor.clear_cache()
        no_keys_settings = {
            'DATA_PROTECTION_KEYS': {},
            'DATA_PROTECTION_ACTIVE_KEY_ID': None,
        }
        with override_settings(**no_keys_settings):
            FieldEncryptor.clear_cache()
            with self.assertRaises(ConfigurationError):
                compute_hash('test_value')


@override_settings(**ENCRYPTION_SETTINGS)
class TestEncryptedJSONFieldNonEncrypted(TestCase):
    def test_from_db_value_returns_plain_value_when_not_encrypted(self):
        from django_field_encryption import EncryptedJSONField, FieldEncryptor

        FieldEncryptor.clear_cache()
        field = EncryptedJSONField()
        plain_dict = {'key': 'value'}
        result = field.from_db_value(plain_dict, None, None)
        self.assertEqual(result, plain_dict)

    def test_from_db_value_returns_none_for_none(self):
        from django_field_encryption import EncryptedJSONField

        field = EncryptedJSONField()
        result = field.from_db_value(None, None, None)
        self.assertIsNone(result)


@override_settings(**ENCRYPTION_SETTINGS)
class TestBlindIndexField(TestCase):
    @classmethod
    def setUpClass(cls):
        from django.db import connection, models

        from django_field_encryption import (
            BlindIndexField,
            EncryptedCharField,
            FieldEncryptor,
        )

        FieldEncryptor.clear_cache()

        class UserProfile(models.Model):
            email = EncryptedCharField(max_length=255, null=True, blank=True)
            email_hash = BlindIndexField(
                'email', unique=True, db_index=True, null=True, blank=True
            )

            class Meta:
                app_label = 'tests'

        cls.UserProfile = UserProfile

        with connection.schema_editor() as schema_editor:
            schema_editor.create_model(UserProfile)

        super().setUpClass()

    @classmethod
    def tearDownClass(cls):
        pass

    def test_hash_auto_computed_on_save(self):
        from django_field_encryption import compute_hash

        profile = self.UserProfile.objects.create(email='user@example.com')
        profile.refresh_from_db()
        expected_hash = compute_hash('user@example.com')
        self.assertEqual(profile.email_hash, expected_hash)

    def test_hash_is_deterministic(self):
        from django_field_encryption import compute_hash

        profile = self.UserProfile.objects.create(email='deterministic@example.com')
        profile.refresh_from_db()
        self.assertEqual(profile.email_hash, compute_hash('deterministic@example.com'))

    def test_hash_differs_for_different_values(self):
        profile1 = self.UserProfile.objects.create(email='a@example.com')
        profile2 = self.UserProfile.objects.create(email='b@example.com')
        self.assertNotEqual(profile1.email_hash, profile2.email_hash)

    def test_hash_is_none_for_none_source(self):
        profile = self.UserProfile.objects.create(email=None)
        profile.refresh_from_db()
        self.assertIsNone(profile.email_hash)

    def test_hash_is_none_for_empty_string_source(self):
        profile = self.UserProfile.objects.create(email='')
        profile.refresh_from_db()
        self.assertIsNone(profile.email_hash)

    def test_unique_constraint_enforced(self):
        from django.db import IntegrityError

        self.UserProfile.objects.create(email='unique@example.com')
        with self.assertRaises(IntegrityError):
            self.UserProfile.objects.create(email='unique@example.com')

    def test_lookup_by_hash(self):
        from django_field_encryption import compute_hash

        self.UserProfile.objects.create(email='lookup@example.com')
        found = self.UserProfile.objects.get(
            email_hash=compute_hash('lookup@example.com')
        )
        self.assertEqual(found.email, 'lookup@example.com')

    def test_hash_updates_on_email_change(self):
        from django_field_encryption import compute_hash

        profile = self.UserProfile.objects.create(email='old@example.com')
        profile.email = 'new@example.com'
        profile.save()
        profile.refresh_from_db()
        self.assertEqual(profile.email_hash, compute_hash('new@example.com'))

    def test_deconstruct_for_migrations(self):
        from django_field_encryption import BlindIndexField

        field = BlindIndexField('email', unique=True, db_index=True)
        name, path, args, kwargs = field.deconstruct()
        self.assertEqual(args[0], 'email')
        self.assertNotIn('max_length', kwargs)
        self.assertNotIn('editable', kwargs)
        self.assertTrue(kwargs.get('unique'))
        self.assertTrue(kwargs.get('db_index'))

    def test_field_not_editable_by_default(self):
        from django_field_encryption import BlindIndexField

        field = BlindIndexField('email')
        self.assertFalse(field.editable)

    def test_default_max_length_is_64(self):
        from django_field_encryption import BlindIndexField

        field = BlindIndexField('email')
        self.assertEqual(field.max_length, 64)


@override_settings(
    DATA_PROTECTION_KEYS={'v1': TEST_MASTER_KEY, 'v2': TEST_MASTER_KEY_V2},
    DATA_PROTECTION_ACTIVE_KEY_ID='v2',
)
class TestFieldKeyPinning(TestCase):
    def setUp(self):
        from django_field_encryption import FieldEncryptor

        FieldEncryptor.clear_cache()
        self.encryptor = FieldEncryptor

    def test_encrypt_with_explicit_key_id(self):
        encrypted = self.encryptor.encrypt('secret', key_id='v1')
        self.assertTrue(encrypted.startswith('v1:'))
        decrypted = self.encryptor.decrypt(encrypted)
        self.assertEqual(decrypted, 'secret')

    def test_encrypt_without_key_id_uses_active(self):
        encrypted = self.encryptor.encrypt('secret')
        self.assertTrue(encrypted.startswith('v2:'))

    def test_encrypted_field_with_pinned_key_id(self):
        from django_field_encryption import EncryptedCharField

        field = EncryptedCharField(key_id='v1')
        encrypted = field.get_prep_value('test')
        self.assertTrue(encrypted.startswith('v1:'))
        decrypted = field.to_python(encrypted)
        self.assertEqual(decrypted, 'test')

    def test_encrypted_field_without_key_id_uses_active(self):
        from django_field_encryption import EncryptedCharField

        field = EncryptedCharField()
        encrypted = field.get_prep_value('test')
        self.assertTrue(encrypted.startswith('v2:'))

    def test_deconstruct_includes_key_id(self):
        from django_field_encryption import EncryptedCharField

        field = EncryptedCharField(key_id='v1')
        name, path, args, kwargs = field.deconstruct()
        self.assertEqual(kwargs.get('key_id'), 'v1')

    def test_deconstruct_omits_key_id_when_none(self):
        from django_field_encryption import EncryptedCharField

        field = EncryptedCharField()
        name, path, args, kwargs = field.deconstruct()
        self.assertNotIn('key_id', kwargs)

    def test_decryption_ignores_field_key_id(self):
        from django_field_encryption import EncryptedCharField

        v1_encrypted = self.encryptor.encrypt('secret', key_id='v1')
        field = EncryptedCharField(key_id='v2')
        decrypted = field.to_python(v1_encrypted)
        self.assertEqual(decrypted, 'secret')


class TestBlindIndexFieldKeyPinningDeconstruct(TestCase):
    def test_deconstruct_includes_key_id(self):
        from django_field_encryption import BlindIndexField

        field = BlindIndexField('email', key_id='v1')
        name, path, args, kwargs = field.deconstruct()
        self.assertEqual(kwargs.get('key_id'), 'v1')

    def test_deconstruct_omits_key_id_when_none(self):
        from django_field_encryption import BlindIndexField

        field = BlindIndexField('email')
        name, path, args, kwargs = field.deconstruct()
        self.assertNotIn('key_id', kwargs)

    @override_settings(**ENCRYPTION_SETTINGS)
    def test_compute_hash_with_explicit_key_id(self):
        from django_field_encryption import FieldEncryptor, compute_hash

        FieldEncryptor.clear_cache()
        hash_v1 = compute_hash('test', key_id='v1')
        self.assertEqual(len(hash_v1), 64)

    @override_settings(
        DATA_PROTECTION_KEYS={'v1': TEST_MASTER_KEY, 'v2': TEST_MASTER_KEY_V2},
        DATA_PROTECTION_ACTIVE_KEY_ID='v2',
    )
    def test_hash_differs_by_key_id(self):
        from django_field_encryption import FieldEncryptor, compute_hash

        FieldEncryptor.clear_cache()
        hash_v1 = compute_hash('same_value', key_id='v1')
        hash_v2 = compute_hash('same_value', key_id='v2')
        self.assertNotEqual(hash_v1, hash_v2)


@override_settings(**ENCRYPTION_SETTINGS)
class TestAADCopyPasteProtection(TestCase):
    def setUp(self):
        from django_field_encryption import FieldEncryptor

        FieldEncryptor.clear_cache()
        self.encryptor = FieldEncryptor

    def test_aad_roundtrip(self):
        aad = b'test:model:1'
        encrypted = self.encryptor.encrypt('secret', aad=aad)
        self.assertEqual(self.encryptor.decrypt(encrypted, aad=aad), 'secret')

    def test_wrong_aad_raises_decryption_error(self):
        from django_field_encryption.exceptions import DecryptionError

        encrypted = self.encryptor.encrypt('secret', aad=b'context_a')
        with self.assertRaises(DecryptionError):
            self.encryptor.decrypt(encrypted, aad=b'context_b')
        with self.assertRaises(DecryptionError):
            self.encryptor.decrypt(encrypted, aad=None)

    def test_bound_field_uses_aad_prevents_cross_context_swap(self):
        from django.db import models

        from django_field_encryption import EncryptedCharField
        from django_field_encryption.exceptions import DecryptionError

        class AADModelA(models.Model):
            secret = EncryptedCharField(max_length=255)

            class Meta:
                app_label = 'tests'

        class AADModelB(models.Model):
            field_x = EncryptedCharField(max_length=255)
            field_y = EncryptedCharField(max_length=255)

            class Meta:
                app_label = 'tests'

        field_a = AADModelA._meta.get_field('secret')
        field_x = AADModelB._meta.get_field('field_x')
        field_y = AADModelB._meta.get_field('field_y')

        enc_a = field_a._encrypt_value('from_a')
        enc_x = field_x._encrypt_value('from_x')
        enc_y = field_y._encrypt_value('from_y')

        for src, dst in [
            (enc_a, field_x),
            (enc_x, field_a),
            (enc_x, field_y),
            (enc_y, field_x),
        ]:
            with self.assertRaises(DecryptionError):
                dst._decrypt_value(src)

    def test_unbound_field_works_without_aad(self):
        from django_field_encryption import EncryptedCharField

        field = EncryptedCharField()
        encrypted = field._encrypt_value('secret')
        self.assertEqual(field._decrypt_value(encrypted), 'secret')

    def test_backward_compat_old_ciphertext(self):
        from django.db import models

        from django_field_encryption import EncryptedCharField

        old = self.encryptor.encrypt('legacy', aad=None)

        class AADCompatModel(models.Model):
            secret = EncryptedCharField(max_length=255)

            class Meta:
                app_label = 'tests'

        field = AADCompatModel._meta.get_field('secret')
        self.assertEqual(field._decrypt_value(old), 'legacy')
