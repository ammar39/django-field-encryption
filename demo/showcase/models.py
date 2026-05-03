from django.db import models

from django_field_encryption import (
    EncryptedCharField,
    EncryptedTextField,
    EncryptedJSONField,
    encrypted_file_storage,
)


class Profile(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField()
    ssn = EncryptedCharField(
        max_length=20, help_text='Social Security Number (encrypted)'
    )
    notes = EncryptedTextField(blank=True, help_text='Private notes (encrypted)')
    preferences = EncryptedJSONField(
        default=dict,
        blank=True,
        help_text='User preferences as JSON (encrypted)',
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.name} ({self.email})'


class Document(models.Model):
    title = models.CharField(max_length=200)
    file = models.FileField(
        storage=encrypted_file_storage,
        upload_to='documents/%Y/%m/',
        help_text='Uploaded file will be encrypted at rest',
    )
    description = models.TextField(blank=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-uploaded_at']

    def __str__(self):
        return self.title
