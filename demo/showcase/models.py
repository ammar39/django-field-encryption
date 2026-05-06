from django.db import models

from django_field_encryption import (
    BlindIndexField,
    EncryptedCharField,
    EncryptedDateField,
    EncryptedDateTimeField,
    EncryptedEmailField,
    EncryptedFileStorage,
    EncryptedIntegerField,
    EncryptedJSONField,
    EncryptedTextField,
)


class Profile(models.Model):
    name = models.CharField(max_length=100)
    email = EncryptedEmailField(help_text='Encrypted email')
    ssn = EncryptedCharField(
        max_length=20, help_text='Social Security Number (encrypted)'
    )
    ssn_hash = BlindIndexField('ssn', unique=True, db_index=True)
    notes = EncryptedTextField(blank=True, help_text='Private notes (encrypted)')
    preferences = EncryptedJSONField(
        default=dict,
        blank=True,
        help_text='User preferences as JSON (encrypted)',
    )
    age = EncryptedIntegerField(null=True, blank=True, help_text='Age (encrypted)')
    birth_date = EncryptedDateField(
        null=True, blank=True, help_text='Date of birth (encrypted)'
    )
    created_at = EncryptedDateTimeField(auto_now_add=True)
    updated_at = EncryptedDateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.name} ({self.email})'


class Document(models.Model):
    title = models.CharField(max_length=200)
    file = models.FileField(
        storage=EncryptedFileStorage,
        upload_to='documents/%Y/%m/',
        help_text='Uploaded file will be encrypted at rest',
    )
    description = EncryptedTextField(blank=True, help_text='Encrypted description')
    encrypted_pages = EncryptedIntegerField(
        default=0, help_text='Number of encrypted pages'
    )
    uploaded_at = EncryptedDateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-uploaded_at']

    def __str__(self):
        return self.title
