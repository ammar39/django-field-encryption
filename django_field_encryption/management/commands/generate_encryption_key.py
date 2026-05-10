from django.core.management.base import BaseCommand

from django_field_encryption.encryption import generate_master_key


class Command(BaseCommand):
    help = 'Generate a new encryption master key and output the configuration.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--key-id',
            type=str,
            default=None,
            help='Key ID for the new key (e.g., v1, v2). Auto-detects next version if not provided.',
        )
        parser.add_argument(
            '--set-active',
            action='store_true',
            help='Also output the setting to make this key the active key.',
        )

    def handle(self, *args, **options):
        key_id = options['key_id']
        set_active = options['set_active']

        master_key = generate_master_key()

        self.stdout.write(self.style.SUCCESS('Generated new encryption key:'))
        self.stdout.write('')
        self.stdout.write(f'  Key ID: {key_id}')
        self.stdout.write(f'  Key:    {master_key}')
        self.stdout.write('')

        self.stdout.write(self.style.SUCCESS('Add to your Django settings:'))
        self.stdout.write('')
        if set_active:
            self.stdout.write('  DATA_PROTECTION_KEYS = {')
            self.stdout.write(f"      '{key_id}': '{master_key}',")
            self.stdout.write('  }')
            self.stdout.write(f"  DATA_PROTECTION_ACTIVE_KEY_ID = '{key_id}'")
        else:
            self.stdout.write('  DATA_PROTECTION_KEYS = {')
            self.stdout.write('      # ... existing keys ...')
            self.stdout.write(f"      '{key_id}': '{master_key}',")
            self.stdout.write('  }')
        self.stdout.write('')
