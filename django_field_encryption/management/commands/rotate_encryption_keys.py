from django.core.management.base import BaseCommand

from django_field_encryption import FieldEncryptor, get_active_key_id, get_keys_config
from django_field_encryption.encryption import PREFIX_SEPARATOR
from django_field_encryption.fields import ENCRYPTED_FIELD_CLASSES


class Command(BaseCommand):
    help = 'Rotate encryption keys for all models with encrypted fields.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be rotated without making changes.',
        )
        parser.add_argument(
            '--batch-size',
            type=int,
            default=1000,
            help='Number of records to process per batch (default: 1000).',
        )
        parser.add_argument(
            '--app-label',
            type=str,
            default=None,
            help='Only rotate keys for models in the specified app.',
        )

    def handle(self, *args, **options):
        dry_run = options['dry_run']
        batch_size = options['batch_size']
        app_label = options['app_label']

        active_key_id = get_active_key_id()
        keys_config = get_keys_config()

        if not active_key_id or not keys_config:
            self.stderr.write(
                self.style.ERROR(  # type: ignore[union-attr]
                    'No encryption keys configured. '
                    'Set DATA_PROTECTION_KEYS and DATA_PROTECTION_ACTIVE_KEY_ID in settings.'
                )
            )
            return

        self.stdout.write(f'Active key: {active_key_id}')
        self.stdout.write(f'Known keys: {", ".join(sorted(keys_config.keys()))}')
        self.stdout.write('')

        from django.apps import apps

        total_rotated = 0
        total_skipped = 0

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

            self.stdout.write(f'Processing {model._meta.label}...')

            for field in encrypted_fields:
                field_name = field.name
                queryset = model.objects.all()
                total = queryset.count()

                if total == 0:
                    self.stdout.write(f'  {field_name}: no records, skipping')
                    continue

                rotated = 0
                skipped = 0

                for offset in range(0, total, batch_size):
                    raw_values = list(
                        queryset[offset : offset + batch_size].values_list(
                            'pk', field_name
                        )
                    )
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
                        objs = []
                        for pk, val in updates:
                            obj = model(pk=pk)
                            setattr(obj, field_name, val)
                            objs.append(obj)
                        model.objects.bulk_update(objs, [field_name])

                self.stdout.write(
                    f'  {field_name}: {rotated} rotated, {skipped} skipped (out of {total})'
                )
                total_rotated += rotated
                total_skipped += skipped

        self.stdout.write('')
        if dry_run:
            self.stdout.write(
                self.style.WARNING(  # type: ignore[union-attr]
                    f'Dry run: {total_rotated} records would be rotated, '
                    f'{total_skipped} already using active key.'
                )
            )
        else:
            self.stdout.write(
                self.style.SUCCESS(  # type: ignore[union-attr]
                    f'Rotation complete: {total_rotated} records rotated, '
                    f'{total_skipped} already using active key.'
                )
            )
