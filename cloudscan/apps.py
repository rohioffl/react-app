from django.apps import AppConfig
import os
from mongoengine import connect
from mongoengine.connection import get_connection


class CloudscanConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'cloudscan'

    def ready(self):
        """Connect to MongoDB if ``MONGODB_URI`` is configured."""
        mongo_uri = os.getenv("MONGODB_URI")
        if not mongo_uri:
            return
        try:
            # only connect if no default connection is registered
            get_connection()
        except Exception:
            connect(host=mongo_uri)
