from django.apps import AppConfig
import logging
import os
from mongoengine import connect
from mongoengine.connection import get_connection


class CloudscanConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'cloudscan'

    def ready(self):
        """Connect to MongoDB on startup and log the outcome."""
        mongo_uri = os.getenv("MONGODB_URI")
        if not mongo_uri:
            return

        logger = logging.getLogger(__name__)

        try:
            # Only connect if no default connection is registered
            get_connection()
            logger.info("\u2705 MongoDB connection already established.")
        except Exception:
            try:
                connect(host=mongo_uri)
                logger.info("\u2705 MongoDB connection established.")
            except Exception as exc:
                logger.error("\u274c Failed to connect to MongoDB: %s", exc)
