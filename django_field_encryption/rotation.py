from typing import Any, Optional

from django.apps import apps
from django.db import transaction

from .encryption import PREFIX_SEPARATOR
from .fields import ENCRYPTED_FIELD_CLASSES


def rotate_keys(
    app_label: Optional[str] = None,
    batch_size: int = 1000,
    dry_run: bool = False,
) -> dict[str, dict[str, int]]:
    """Rotate encryption keys for all models with encrypted fields.

    Designed to be called from custom migrations or management commands.

    Args:
        app_label: Only rotate keys for models in the specified app.
        batch_size: Number of records to process per batch.
        dry_run: If True, count what would be rotated without making changes.

    Returns:
        A dict mapping ``'app_label.ModelName.field_name'`` to
        ``{'rotated': int, 'skipped': int}``.
    """
    from . import FieldEncryptor, get_active_key_id, get_keys_config

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

        for field in encrypted_fields:
            field_name = field.name
            result_key = f'{model._meta.label}.{field_name}'
            rotated = 0
            skipped = 0
            last_pk: Any = None

            queryset = model.objects.all().order_by('pk')

            while True:
                batch_qs = queryset
                if last_pk is not None:
                    batch_qs = batch_qs.filter(pk__gt=last_pk)
                raw_values = list(batch_qs[:batch_size].values_list('pk', field_name))
                if not raw_values:
                    break

                updates = []

                for pk, raw_value in raw_values:
                    if not raw_value:
                        skipped += 1
                        continue

                    raw_str = str(raw_value)

                    if PREFIX_SEPARATOR not in raw_str:
                        skipped += 1
                        continue

                    old_key_id = raw_str.split(PREFIX_SEPARATOR, 1)[0]
                    if old_key_id == active_key_id:
                        skipped += 1
                        continue

                    try:
                        plaintext = FieldEncryptor.decrypt(raw_str)
                    except Exception:
                        skipped += 1
                        continue

                    updates.append((pk, plaintext))
                    rotated += 1

                if updates and not dry_run:
                    with transaction.atomic():
                        objs = []
                        for pk, val in updates:
                            obj = model(pk=pk)
                            setattr(obj, field_name, val)
                            objs.append(obj)
                        model.objects.bulk_update(objs, [field_name])

                last_pk = raw_values[-1][0]

            results[result_key] = {'rotated': rotated, 'skipped': skipped}

    return results
