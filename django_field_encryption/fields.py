import json as json_module
from typing import TYPE_CHECKING, Any, Optional

from django.core.exceptions import FieldError, ImproperlyConfigured, ValidationError
from django.core.validators import MaxLengthValidator
from django.db import models
from django.db.models.signals import pre_save

from .encryption import FieldEncryptor, compute_hash
from .exceptions import DecryptionError, EncryptionError

if TYPE_CHECKING:
    Base = models.Field
else:
    Base = object


class EncryptedMaxLengthValidator(MaxLengthValidator):
    def clean(self, x):
        if isinstance(x, str) and FieldEncryptor.is_encrypted(x):
            try:
                x = FieldEncryptor.decrypt(x)
            except DecryptionError:
                pass
        return len(x)


class EncryptedFieldMixin(Base):
    _field_path: str = ''
    default_validators: list = []

    def __init__(
        self,
        *args: Any,
        strict: bool = True,
        key_id: Optional[str] = None,
        **kwargs: Any,
    ):
        if kwargs.get('primary_key'):
            raise ImproperlyConfigured(
                f'{self.__class__.__name__} does not support primary_key=True.'
            )
        if kwargs.get('unique'):
            raise ImproperlyConfigured(
                f'{self.__class__.__name__} does not support unique=True.'
            )
        if kwargs.get('db_index'):
            raise ImproperlyConfigured(
                f'{self.__class__.__name__} does not support db_index=True.'
            )
        self._strict = strict
        self._key_id = key_id
        super().__init__(*args, **kwargs)

    def get_lookup(self, lookup_name):
        if lookup_name != 'isnull':
            raise FieldError(
                f"{self.__class__.__name__} does not support '{lookup_name}' lookups. "
                'Use a BlindIndexField for searchable encrypted fields.'
            )
        return super().get_lookup(lookup_name)  # type: ignore[misc]

    def get_prep_value(self, value):
        if value is None:
            return value
        return self._encrypt_value(value)

    def get_db_prep_value(self, value, connection, prepared=False):
        if value is None:
            return value
        if not prepared:
            value = self.get_prep_value(value)
        return value

    def deconstruct(self):
        name, path, args, kwargs = super().deconstruct()
        if self._field_path:
            path = self._field_path
        if not self._strict:
            kwargs['strict'] = False
        if self._key_id:
            kwargs['key_id'] = self._key_id
        return name, path, args, kwargs

    def _decrypt_value(self, value):
        if value is None or value == '' or not isinstance(value, str):
            return value
        if not self.is_encrypted(value):
            if not self._strict:
                return value
            if ':' in value:
                key_id = value.split(':', 1)[0]
                from .conf import _get_keys_config

                if key_id in _get_keys_config():
                    return FieldEncryptor.decrypt(value)
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
        decrypted = self._decrypt_value(value)
        if decrypted is None or decrypted == '':
            return decrypted
        try:
            return super().to_python(decrypted)
        except (ValueError, TypeError, ValidationError):
            return decrypted

    def to_python(self, value):
        if value is None or value == '':
            return value
        value = self._decrypt_value(value)
        if value is None or value == '':
            return value
        try:
            return super().to_python(value)
        except (ValueError, TypeError, ValidationError):
            return value

    def _encrypt_value(self, value):
        if value is None:
            return value
        try:
            return FieldEncryptor.encrypt(str(value), key_id=self._key_id)
        except EncryptionError:
            if self._strict:
                raise
            return value

    @staticmethod
    def is_encrypted(value):
        return FieldEncryptor.is_encrypted(value)

    def _get_underlying_validators(self):
        for base in self.__class__.__bases__:
            if base is EncryptedFieldMixin:
                continue
            if base is not object and hasattr(base, 'default_validators'):
                return list(base.default_validators)
        return []

    @property
    def validators(self):
        if hasattr(self, '_validators'):
            return list(self.default_validators) + list(self._validators)
        return list(self._get_underlying_validators())

    @validators.setter
    def validators(self, value):
        self._validators = value

    def db_type(self, connection):
        return 'text'

    def get_internal_type(self):
        return 'CharField'


class EncryptedCharField(EncryptedFieldMixin, models.TextField):
    _field_path = 'django_field_encryption.fields.EncryptedCharField'
    description = 'AES-256-GCM encrypted CharField stored as TextField'

    def __init__(
        self,
        *args: Any,
        strict: bool = True,
        max_length: int = 255,
        key_id: Optional[str] = None,
        **kwargs: Any,
    ):
        kwargs.pop('max_length', None)
        super().__init__(*args, strict=strict, key_id=key_id, **kwargs)
        self.max_length = max_length

    @property
    def validators(self):
        if hasattr(self, '_validators'):
            return (
                list(self.default_validators)
                + list(self._validators)
                + [EncryptedMaxLengthValidator(self.max_length)]
            )
        return [EncryptedMaxLengthValidator(self.max_length)]

    def deconstruct(self):
        name, path, args, kwargs = super().deconstruct()
        if self.max_length != 255:
            kwargs['max_length'] = self.max_length
        kwargs.pop('validators', None)
        return name, path, args, kwargs


class EncryptedJSONField(EncryptedFieldMixin, models.TextField):
    _field_path = 'django_field_encryption.fields.EncryptedJSONField'
    description = 'AES-256-GCM encrypted JSONField stored as TextField'

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
        return self._decrypt_and_parse(value)

    def get_prep_value(self, value):
        if value is None:
            return value
        json_str = json_module.dumps(value, default=str)
        return self._encrypt_value(json_str)


class EncryptedTextField(EncryptedFieldMixin, models.TextField):
    _field_path = 'django_field_encryption.fields.EncryptedTextField'
    description = 'AES-256-GCM encrypted TextField'


class EncryptedDateTimeField(EncryptedFieldMixin, models.DateTimeField):
    _field_path = 'django_field_encryption.fields.EncryptedDateTimeField'
    description = 'AES-256-GCM encrypted DateTimeField'


class EncryptedDateField(EncryptedFieldMixin, models.DateField):
    _field_path = 'django_field_encryption.fields.EncryptedDateField'
    description = 'AES-256-GCM encrypted DateField'


class EncryptedIntegerField(EncryptedFieldMixin, models.IntegerField):
    _field_path = 'django_field_encryption.fields.EncryptedIntegerField'
    description = 'AES-256-GCM encrypted IntegerField'


class EncryptedEmailField(EncryptedFieldMixin, models.EmailField):
    _field_path = 'django_field_encryption.fields.EncryptedEmailField'
    description = 'AES-256-GCM encrypted EmailField'


ENCRYPTED_FIELD_CLASSES: tuple[type[EncryptedFieldMixin], ...] = (
    EncryptedCharField,
    EncryptedDateField,
    EncryptedDateTimeField,
    EncryptedEmailField,
    EncryptedIntegerField,
    EncryptedJSONField,
    EncryptedTextField,
)


class BlindIndexField(models.CharField):
    """Auto-computed HMAC-SHA256 index for an encrypted field.

    Enables unique lookups on encrypted data without decrypting.

    Usage:
        class UserProfile(models.Model):
            email = EncryptedCharField(max_length=255)
            email_hash = BlindIndexField('email', unique=True, db_index=True)
    """

    def __init__(self, source_field: str, key_id: Optional[str] = None, **kwargs: Any):
        kwargs.setdefault('max_length', 64)
        kwargs.setdefault('editable', False)
        self._source_field = source_field
        self._key_id = key_id
        super().__init__(**kwargs)

    def contribute_to_class(self, cls, name, **kwargs: Any):
        super().contribute_to_class(cls, name, **kwargs)
        pre_save.connect(self._compute_hash, sender=cls)

    def _compute_hash(self, sender, instance, **kwargs: Any):
        source_value = getattr(instance, self._source_field, None)
        if source_value is None or source_value == '':
            setattr(instance, self.attname or '', None)
            return
        hash_value = compute_hash(str(source_value), key_id=self._key_id)
        setattr(instance, self.attname or '', hash_value)

    def deconstruct(self):
        name, path, args, kwargs = super().deconstruct()
        args = (self._source_field,) + tuple(args)
        if kwargs.get('max_length') == 64:
            kwargs.pop('max_length', None)
        if kwargs.get('editable') is False:
            kwargs.pop('editable', None)
        if self._key_id:
            kwargs['key_id'] = self._key_id
        return name, path, list(args), kwargs
