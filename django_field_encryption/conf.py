import base64

from django.core.exceptions import ImproperlyConfigured

from .exceptions import ConfigurationError, InvalidKeyError

PREFIX_SEPARATOR = ':'
NONCE_LENGTH = 12


def _get_keys_config() -> dict[str, str]:
    try:
        from django.conf import settings

        return getattr(settings, 'DATA_PROTECTION_KEYS', {})
    except (ImproperlyConfigured, RuntimeError):
        return {}


def _get_active_key_id() -> str:
    try:
        from django.conf import settings

        key_id = getattr(settings, 'DATA_PROTECTION_ACTIVE_KEY_ID', None)
        if key_id:
            return key_id
    except (ImproperlyConfigured, RuntimeError):
        pass

    raise ConfigurationError(
        'DATA_PROTECTION_ACTIVE_KEY_ID is required. '
        'Set it in settings to specify which key to use for encryption.'
    )


def _get_master_key(key_id: str) -> bytes:
    if not key_id:
        raise ConfigurationError('key_id cannot be empty')
    keys = _get_keys_config()
    if not keys:
        raise ConfigurationError(
            'DATA_PROTECTION_KEYS is not configured', key_id=key_id
        )
    if key_id not in keys:
        raise InvalidKeyError(f'Unknown encryption key_id: {key_id}', key_id=key_id)
    raw = keys[key_id]
    if isinstance(raw, str):
        raw = raw.encode()
    if len(raw) == 44:
        try:
            decoded = base64.urlsafe_b64decode(raw)
            if len(decoded) == 32:
                return decoded
        except Exception:
            pass
    if len(raw) != 32:
        raise InvalidKeyError(
            f'Master key for key_id={key_id!r} must be 32 bytes, got {len(raw)}',
            key_id=key_id,
            key_length=len(raw),
        )
    return raw


def get_keys_config() -> dict[str, str]:
    return _get_keys_config()


def get_active_key_id() -> str:
    return _get_active_key_id()


def get_master_key(key_id: str) -> bytes:
    return _get_master_key(key_id)
