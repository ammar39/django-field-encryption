import json as json_module

from django.db import models

from .encryption import PREFIX_SEPARATOR, FieldEncryptor
from .exceptions import DecryptionError, EncryptionError


class EncryptedFieldMixin:
    def __init__(self, *args, strict=False, **kwargs):
        self._strict = strict
        super().__init__(*args, **kwargs)

    def _decrypt_value(self, value):
        if value is None or value == '':
            return value
        try:
            return FieldEncryptor.decrypt(value)
        except DecryptionError:
            if self._strict:
                raise
            return value
        except Exception:
            if self._strict:
                raise
            return value

    def from_db_value(self, value, expression, connection):
        return self._decrypt_value(value)

    def to_python(self, value):
        if value is None or value == '':
            return value
        if isinstance(value, str) and PREFIX_SEPARATOR in value:
            return self._decrypt_value(value)
        return value

    def _encrypt_value(self, value):
        if value is None or value == '':
            return value
        try:
            return FieldEncryptor.encrypt(str(value))
        except EncryptionError:
            if self._strict:
                raise
            return value


class EncryptedCharField(EncryptedFieldMixin, models.TextField):
    description = 'AES-256-GCM encrypted CharField stored as TextField'

    def __init__(self, *args, strict=False, **kwargs):
        kwargs.setdefault('max_length', None)
        self._char_max_length = kwargs.pop('char_max_length', 255)
        super().__init__(*args, strict=strict, **kwargs)

    def get_prep_value(self, value):
        return self._encrypt_value(value)

    def deconstruct(self):
        name, path, args, kwargs = super().deconstruct()
        path = 'django_field_encryption.fields.EncryptedCharField'
        if self._char_max_length != 255:
            kwargs['char_max_length'] = self._char_max_length
        if self._strict:
            kwargs['strict'] = self._strict
        kwargs.pop('max_length', None)
        return name, path, args, kwargs


class EncryptedTextField(EncryptedFieldMixin, models.TextField):
    description = 'AES-256-GCM encrypted TextField'

    def get_prep_value(self, value):
        return self._encrypt_value(value)

    def deconstruct(self):
        name, path, args, kwargs = super().deconstruct()
        path = 'django_field_encryption.fields.EncryptedTextField'
        if self._strict:
            kwargs['strict'] = self._strict
        return name, path, args, kwargs


class EncryptedJSONField(models.TextField):
    description = 'AES-256-GCM encrypted JSONField stored as TextField'

    def __init__(self, *args, strict=False, **kwargs):
        self._strict = strict
        super().__init__(*args, **kwargs)

    def _decrypt_and_parse(self, value):
        try:
            decrypted = FieldEncryptor.decrypt(value)
        except DecryptionError:
            if self._strict:
                raise
            return value
        except Exception:
            if self._strict:
                raise
            return value
        if isinstance(decrypted, str):
            try:
                return json_module.loads(decrypted)
            except (json_module.JSONDecodeError, ValueError) as err:
                if self._strict:
                    raise ValueError(f'Decrypted value is not valid JSON: {decrypted}') from err
                return decrypted
        return decrypted

    def from_db_value(self, value, expression, connection):
        if value is None:
            return value
        if isinstance(value, str) and PREFIX_SEPARATOR in value:
            return self._decrypt_and_parse(value)
        return value

    def to_python(self, value):
        if value is None:
            return value
        if isinstance(value, str) and PREFIX_SEPARATOR in value:
            return self._decrypt_and_parse(value)
        return value

    def get_prep_value(self, value):
        if value is None:
            return value
        json_str = json_module.dumps(value, default=str)
        try:
            return FieldEncryptor.encrypt(json_str)
        except EncryptionError:
            if self._strict:
                raise
            return value

    def deconstruct(self):
        name, path, args, kwargs = super().deconstruct()
        path = 'django_field_encryption.fields.EncryptedJSONField'
        if self._strict:
            kwargs['strict'] = self._strict
        return name, path, args, kwargs
