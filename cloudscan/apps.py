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
            print("❌ MONGODB_URI not set. Skipping MongoDB connection.")
            return

        logger = logging.getLogger(__name__)

        try:
            # Try to get existing connection; if it fails, we'll connect.
            conn = get_connection()
            # Actually try to ping MongoDB for real connection test
            conn.server_info()
            logger.info("✅ MongoDB connection already established.")
            print("✅ MongoDB connection already established.")
        except Exception:
            try:
                connect(host=mongo_uri, alias='default', serverSelectionTimeoutMS=3000)
                # Ping the server for confirmation
                get_connection().server_info()
                logger.info("✅ MongoDB connection established.")
                print("✅ MongoDB connection established.")
            except Exception as exc:
                logger.error("❌ Failed to connect to MongoDB: %s", exc)
                print(f"❌ Failed to connect to MongoDB: {exc}")
