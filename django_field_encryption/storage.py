import io

from django.core.files.base import ContentFile, File
from django.core.files.storage import FileSystemStorage

from .encryption import FileEncryptor


class EncryptedFileStorage(FileSystemStorage):
    def _save(self, name, content):
        raw_data = content.read()
        if isinstance(raw_data, str):
            raw_data = raw_data.encode('utf-8')
        encrypted_data, _key_id = FileEncryptor.encrypt(raw_data)
        encrypted_content = ContentFile(encrypted_data)
        encrypted_content.name = content.name if hasattr(content, 'name') else name
        return super()._save(name, encrypted_content)

    def _open(self, name, mode='rb'):
        storage_file = super()._open(name, mode)
        raw_data = storage_file.read()
        decrypted_data = FileEncryptor.decrypt(raw_data)
        buf = io.BytesIO(decrypted_data)
        return File(buf, name=name)

    def is_encrypted(self, name):
        if not self.exists(name):
            return False
        with super()._open(name) as f:
            header = f.read(4)
        return FileEncryptor.is_encrypted(header)


encrypted_file_storage = EncryptedFileStorage()
