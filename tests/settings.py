SECRET_KEY = 'test-secret-key'
DEBUG = True

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
    }
}

INSTALLED_APPS = [
    'django.contrib.contenttypes',
    'django.contrib.auth',
    'django.contrib.admin',
    'django_field_encryption',
]

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
