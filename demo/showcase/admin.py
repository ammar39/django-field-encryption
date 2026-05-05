from django.contrib import admin

from django_field_encryption.admin import (
    EncryptedFieldAdminMixin,
    EncryptedSearchMixin,
)

from .models import Document, Profile


@admin.register(Profile)
class ProfileAdmin(EncryptedSearchMixin, EncryptedFieldAdminMixin, admin.ModelAdmin):
    list_display = ('name', 'email', 'display_ssn', 'created_at')
    search_fields = ('name', 'ssn_hash')
    readonly_fields = ('ssn_hash',)
    encrypted_search_fields = {'ssn': 'ssn_hash'}

    def display_ssn(self, obj):
        return '***encrypted***'

    display_ssn.short_description = 'SSN'


@admin.register(Document)
class DocumentAdmin(EncryptedFieldAdminMixin, admin.ModelAdmin):
    list_display = ('title', 'uploaded_at')
