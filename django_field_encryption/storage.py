import io

from django.core.files.base import ContentFile, File
from django.core.files.storage import FileSystemStorage, Storage

from .encryption import FileEncryptor


class BaseEncryptedStorage(Storage):
    """Encryption wrapper that works with any Django storage backend."""

    max_file_size: int = 100 * 1024 * 1024

    def __init__(self, underlying_storage=None, **kwargs):
        if underlying_storage is None:
            underlying_storage = FileSystemStorage(**kwargs)
        self._storage = underlying_storage
        super().__init__()

    def _save(self, name, content):
        raw_data = content.read()
        if isinstance(raw_data, str):
            raw_data = raw_data.encode('utf-8')
        if self.max_file_size and len(raw_data) > self.max_file_size:
            raise ValueError(
                f'File too large for encrypted storage: {len(raw_data)} bytes '
                f'exceeds max_file_size of {self.max_file_size} bytes. '
                f'AES-GCM requires the full file in memory for authentication tag '
                f'verification. Increase max_file_size if this is intentional.'
            )
        encrypted_data, _key_id = FileEncryptor.encrypt(raw_data)
        encrypted_content = ContentFile(encrypted_data)
        encrypted_content.name = content.name if hasattr(content, 'name') else name
        return self._storage._save(name, encrypted_content)

    def _open(self, name, mode='rb'):
        storage_file = self._storage._open(name, mode)
        raw_data = storage_file.read()
        decrypted_data = FileEncryptor.decrypt(raw_data)
        buf = io.BytesIO(decrypted_data)
        return File(buf, name=name)

    def is_encrypted(self, name):
        if not self.exists(name):
            return False
        with self._storage._open(name) as f:
            header = f.read(4)
        return FileEncryptor.is_encrypted(header)

    def exists(self, name):
        return self._storage.exists(name)

    def delete(self, name):
        return self._storage.delete(name)

    def url(self, name):
        raise NotImplementedError(
            'EncryptedFileStorage.url() is disabled because the underlying '
            'storage serves raw ciphertext. Serve files through a view that '
            'calls storage.open() to decrypt first.'
        )

    def get_valid_name(self, name):
        return self._storage.get_valid_name(name)

    def get_available_name(self, name, max_length=None):
        return self._storage.get_available_name(name, max_length)

    def generate_filename(self, filename):
        return self._storage.generate_filename(filename)

    @property
    def base_location(self):
        return getattr(self._storage, 'base_location', '')

    @property
    def location(self):
        return getattr(self._storage, 'location', '')

    @property
    def path(self):
        if hasattr(self._storage, 'path'):
            return self._storage.path
        raise NotImplementedError(
            f'{self._storage.__class__.__name__} does not support path()'
        )


class EncryptedFileStorage(BaseEncryptedStorage):
    """Encrypted storage backed by the local filesystem."""

    def __init__(self, **kwargs):
        underlying = FileSystemStorage(**kwargs)
        super().__init__(underlying_storage=underlying)

    @classmethod
    def deconstruct(cls):
        return ('django_field_encryption.storage.EncryptedFileStorage', [], {})


encrypted_file_storage = EncryptedFileStorage()
