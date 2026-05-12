from collections.abc import Sequence
from typing import TYPE_CHECKING, Optional

from django.contrib.admin import ModelAdmin
from django.db.models import QuerySet
from django.http import HttpRequest

from .encryption import compute_hash
from .fields import ENCRYPTED_FIELD_CLASSES

if TYPE_CHECKING:
    Base = ModelAdmin
else:
    Base = object


class EncryptedFieldAdminMixin(Base):
    encrypted_field_mask: str = '***encrypted***'
    exclude_encrypted_from_search: bool = True
    show_encrypted_in_readonly: bool = True

    def get_exclude(
        self, request: HttpRequest, obj: Optional[object] = None
    ) -> Optional[Sequence[str]]:
        excluded: Sequence[str] = super().get_exclude(request, obj) or ()  # type: ignore[misc]
        encrypted = self._get_encrypted_field_names()
        if self.show_encrypted_in_readonly:
            excluded = tuple(set(excluded) | set(encrypted))
        return excluded or None

    def get_readonly_fields(
        self, request: HttpRequest, obj: Optional[object] = None
    ) -> Sequence[str]:
        readonly: Sequence[str] = super().get_readonly_fields(request, obj) or ()  # type: ignore[misc]
        if not self.show_encrypted_in_readonly:
            return readonly
        encrypted = self._get_encrypted_field_names()
        return tuple(set(readonly) | set(encrypted))

    def get_search_fields(self, request: HttpRequest) -> Optional[Sequence[str]]:
        search: Sequence[str] = super().get_search_fields(request) or ()  # type: ignore[misc]
        if self.exclude_encrypted_from_search:
            encrypted = set(self._get_encrypted_field_names())
            search = tuple(f for f in search if f not in encrypted)
        return search

    def get_list_display(self, request: HttpRequest) -> Optional[Sequence[str]]:
        display = super().get_list_display(request)  # type: ignore[misc]
        if display is None:
            display = getattr(self, 'list_display', None)
            if display is None:
                return None
        encrypted = set(self._get_encrypted_field_names())
        return tuple(
            self._masked_display_name(f) if f in encrypted else f for f in display
        )

    def _get_encrypted_field_names(self) -> list[str]:
        return [
            f.name  # type: ignore[typeddict-item]
            for f in self.model._meta.fields
            if isinstance(f, ENCRYPTED_FIELD_CLASSES)
        ]

    def _masked_display_name(self, field_name: str) -> str:
        method_name = f'display_{field_name}'
        if hasattr(self, method_name):
            return method_name

        mask = self.encrypted_field_mask

        def _display(
            self_admin: object, _fn: str = field_name, _mask: str = mask
        ) -> str:
            return _mask

        setattr(type(self), method_name, _display)
        return method_name


class EncryptedSearchMixin(Base):
    encrypted_search_fields: dict[str, Optional[str]] = {}

    def get_search_results(
        self,
        request: HttpRequest,
        queryset: QuerySet,
        search_term: str,
    ) -> tuple[QuerySet, bool]:
        queryset, use_distinct = super().get_search_results(
            request, queryset, search_term
        )
        if not search_term:
            return queryset, use_distinct

        for field_name, hash_field_name in self.encrypted_search_fields.items():
            hash_field = hash_field_name or f'{field_name}_hash'
            queryset |= queryset.filter(**{hash_field: compute_hash(search_term)})
        return queryset, use_distinct
