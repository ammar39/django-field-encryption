from typing import Optional


class EncryptionError(Exception):
    """Base exception for all encryption-related errors."""

    pass


class ConfigurationError(EncryptionError):
    """Raised when encryption configuration is invalid or missing."""

    def __init__(self, message: str, key_id: Optional[str] = None):
        super().__init__(message)
        self.key_id = key_id


class InvalidKeyError(EncryptionError):
    """Raised when a key is invalid (wrong format, wrong length, etc.)."""

    def __init__(
        self,
        message: str,
        key_id: Optional[str] = None,
        key_length: Optional[int] = None,
    ):
        super().__init__(message)
        self.key_id = key_id
        self.key_length = key_length


class DecryptionError(EncryptionError):
    """Raised when decryption fails."""

    def __init__(
        self,
        message: str,
        key_id: Optional[str] = None,
        original_exception: Optional[Exception] = None,
    ):
        super().__init__(message)
        self.key_id = key_id
        self.original_exception = original_exception


class EncryptionNotConfiguredError(EncryptionError):
    """Raised when no encryption key is configured."""

    def __init__(self, message: str = 'No active encryption key configured'):
        super().__init__(message)
