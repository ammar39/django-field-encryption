from typing import Any, Optional

from django.apps import apps
from django.db import models
from django.db.models import QuerySet
from django.db.transaction import atomic

from .encryption import PREFIX_SEPARATOR
from .fields import ENCRYPTED_FIELD_CLASSES


def _should_rotate_value(raw_value: Any, active_key_id: str) -> Optional[str]:
    if not raw_value:
        return None

    raw_str = str(raw_value)

    if PREFIX_SEPARATOR not in raw_str:
        return None

    old_key_id = raw_str.split(PREFIX_SEPARATOR, 1)[0]
    if old_key_id == active_key_id:
        return None

    from . import FieldEncryptor

    try:
        return FieldEncryptor.decrypt(raw_str)
    except Exception:
        return None


def _rotate_field_values(
    model: type[models.Model],
    field_name: str,
    batch_size: int = 1000,
    dry_run: bool = False,
) -> dict[str, int]:
    from . import get_active_key_id

    active_key_id = get_active_key_id()
    rotated = 0
    skipped = 0
    last_pk: Any = None

    queryset: QuerySet = model.objects.all().order_by('pk')

    while True:
        batch_qs = queryset
        if last_pk is not None:
            batch_qs = batch_qs.filter(pk__gt=last_pk)
        raw_values = list(batch_qs[:batch_size].values_list('pk', field_name))
        if not raw_values:
            break

        updates = []

        for pk, raw_value in raw_values:
            plaintext = _should_rotate_value(raw_value, active_key_id)
            if plaintext is None:
                skipped += 1
                continue

            updates.append((pk, plaintext))
            rotated += 1

        if updates and not dry_run:
            with atomic():
                objs = []
                for pk, val in updates:
                    obj = model(pk=pk)
                    setattr(obj, field_name, val)
                    objs.append(obj)
                model.objects.bulk_update(objs, [field_name])

        last_pk = raw_values[-1][0]

    return {'rotated': rotated, 'skipped': skipped}


def rotate_model_fields(
    model: type[models.Model],
    field_names: Optional[list[str]] = None,
    batch_size: int = 1000,
    dry_run: bool = False,
) -> dict[str, dict[str, int]]:
    """Rotate encryption keys for one or more fields on a specific model.

    Args:
        model: The Django model class.
        field_names: List of field names to rotate.  If ``None``, all
            encrypted fields on the model are rotated.
        batch_size: Number of records fetched per database query.
        dry_run: If ``True``, no writes are performed.

    Returns:
        A dict mapping ``'field_name'`` to
        ``{'rotated': <count>, 'skipped': <count>}``.

    Raises:
        RuntimeError: If no encryption keys are configured.
    """
    from . import get_active_key_id, get_keys_config

    active_key_id = get_active_key_id()
    keys_config = get_keys_config()

    if not active_key_id or not keys_config:
        raise RuntimeError(
            'No encryption keys configured. '
            'Set DATA_PROTECTION_KEYS and DATA_PROTECTION_ACTIVE_KEY_ID in settings.'
        )

    if field_names is None:
        encrypted_fields = [
            field.name
            for field in model._meta.fields
            if isinstance(field, ENCRYPTED_FIELD_CLASSES)
        ]
    else:
        encrypted_fields = field_names

    results: dict[str, dict[str, int]] = {}

    for field_name in encrypted_fields:
        results[field_name] = _rotate_field_values(
            model, field_name, batch_size=batch_size, dry_run=dry_run
        )

    return results


def rotate_keys(
    app_label: Optional[str] = None,
    batch_size: int = 1000,
    dry_run: bool = False,
) -> dict[str, dict[str, int]]:
    """Rotate encryption keys for all models with encrypted fields.

    Args:
        app_label: If provided, only models in this app are processed.
        batch_size: Number of records fetched per database query.
        dry_run: If ``True``, no writes are performed.

    Returns:
        A dict mapping ``'app_label.ModelName.field_name'`` to
        ``{'rotated': <count>, 'skipped': <count>}``.  ``rotated`` is

    Raises:
        RuntimeError: If no encryption keys are configured.
    """
    from . import get_active_key_id, get_keys_config

    active_key_id = get_active_key_id()
    keys_config = get_keys_config()

    if not active_key_id or not keys_config:
        raise RuntimeError(
            'No encryption keys configured. '
            'Set DATA_PROTECTION_KEYS and DATA_PROTECTION_ACTIVE_KEY_ID in settings.'
        )

    results: dict[str, dict[str, int]] = {}

    for model in apps.get_models():
        if app_label and model._meta.app_label != app_label:
            continue

        encrypted_fields = [
            field
            for field in model._meta.fields
            if isinstance(field, ENCRYPTED_FIELD_CLASSES)
        ]

        if not encrypted_fields:
            continue

        field_results = rotate_model_fields(
            model,
            field_names=[f.name for f in encrypted_fields],
            batch_size=batch_size,
            dry_run=dry_run,
        )

        for field_name, counts in field_results.items():
            result_key = f'{model._meta.label}.{field_name}'
            results[result_key] = counts

    return results
