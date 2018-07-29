from django.apps import AppConfig
from django.db.migrations import state
from django.db.models import options


class DjangoSecureBoxConfig(AppConfig):
    name = 'django_securebox'

    def ready(self):
        from . import models  # noqa
        from . import signals  # noqa
