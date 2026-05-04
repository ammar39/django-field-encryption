import json as json_module
from typing import Any

from django.core.validators import MaxLengthValidator
from django.db import models
from django.db.models.signals import pre_save

from .encryption import PREFIX_SEPARATOR, FieldEncryptor, compute_hash
from .exceptions import DecryptionError, EncryptionError


class EncryptedFieldMixin:
    def __init__(self, *args: Any, strict: bool = False, **kwargs: Any):
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
        if value is None:
            return value
        try:
            return FieldEncryptor.encrypt(str(value))
        except EncryptionError:
            if self._strict:
                raise
            return value


class EncryptedCharField(EncryptedFieldMixin, models.TextField):
    description = 'AES-256-GCM encrypted CharField stored as TextField'
    default_validators = []

    def __init__(
        self,
        *args: Any,
        strict: bool = False,
        char_max_length: int = 255,
        **kwargs: Any,
    ):

        kwargs.setdefault('max_length', None)
        self._char_max_length = char_max_length
        super().__init__(*args, strict=strict, **kwargs)
        self.validators = list(self.validators) + [  # type: ignore[assignment]
            MaxLengthValidator(self._char_max_length)
        ]

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

    def __init__(self, *args: Any, strict: bool = False, **kwargs: Any):
        super().__init__(*args, strict=strict, **kwargs)

    def get_prep_value(self, value):
        return self._encrypt_value(value)

    def deconstruct(self):
        name, path, args, kwargs = super().deconstruct()
        path = 'django_field_encryption.fields.EncryptedTextField'
        if self._strict:
            kwargs['strict'] = self._strict
        return name, path, args, kwargs


class EncryptedJSONField(EncryptedFieldMixin, models.TextField):
    description = 'AES-256-GCM encrypted JSONField stored as TextField'

    def __init__(self, *args: Any, strict: bool = False, **kwargs: Any):
        super().__init__(*args, strict=strict, **kwargs)

    def _decrypt_and_parse(self, value):
        decrypted = self._decrypt_value(value)
        if decrypted is None or decrypted == '' or not isinstance(decrypted, str):
            return decrypted
        try:
            return json_module.loads(decrypted)
        except (json_module.JSONDecodeError, ValueError) as err:
            if self._strict:
                raise ValueError(
                    f'Decrypted value is not valid JSON: {decrypted}'
                ) from err
            return decrypted

    def from_db_value(self, value, expression, connection):
        if value is None:
            return value
        return self._decrypt_and_parse(value)

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
        return self._encrypt_value(json_str)

    def deconstruct(self):
        name, path, args, kwargs = super().deconstruct()
        path = 'django_field_encryption.fields.EncryptedJSONField'
        if self._strict:
            kwargs['strict'] = self._strict
        return name, path, args, kwargs


class BlindIndexField(models.CharField):
    """Auto-computed HMAC-SHA256 index for an encrypted field.

    Enables unique lookups on encrypted data without decrypting.

    Usage:
        class UserProfile(models.Model):
            email = EncryptedCharField(max_length=255)
            email_hash = BlindIndexField('email', unique=True, db_index=True)
    """

    def __init__(self, source_field: str, **kwargs: Any):
        kwargs.setdefault('max_length', 64)
        kwargs.setdefault('editable', False)
        self._source_field = source_field
        super().__init__(**kwargs)

    def contribute_to_class(self, cls, name, **kwargs: Any):
        super().contribute_to_class(cls, name, **kwargs)
        pre_save.connect(self._compute_hash, sender=cls)

    def _compute_hash(self, sender, instance, **kwargs: Any):
        source_value = getattr(instance, self._source_field, None)
        if source_value is None or source_value == '':
            setattr(instance, self.attname or '', None)
            return
        hash_value = compute_hash(str(source_value))
        setattr(instance, self.attname or '', hash_value)

    def deconstruct(self):
        name, path, args, kwargs = super().deconstruct()
        args = (self._source_field,) + tuple(args)
        kwargs.pop('max_length', None)
        kwargs.pop('editable', None)
        return name, path, list(args), kwargs
