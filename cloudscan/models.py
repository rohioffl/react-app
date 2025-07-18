from mongoengine import (
    Document,
    StringField,
    DateTimeField,
    DictField,
    ListField,
    IntField,
)
from datetime import datetime

class AWSScan(Document):
    provider = StringField(default="AWS")
    date = DateTimeField()
    accountId = StringField()
    region = StringField()
    findings = ListField(DictField())

class GCPScan(Document):
    provider = StringField(default="GCP")
    date = DateTimeField()
    accountId = StringField()
    projectId = StringField()
    region = StringField()
    findings = ListField(DictField())


class ScanJob(Document):
    """Track progress and status for async scans."""

    scan_id = StringField(primary_key=True)
    provider = StringField(required=True)
    projectId = StringField()  # For GCP scans
    status = StringField(default="queued")
    progress = IntField(default=0)
    result = DictField()
    created_at = DateTimeField(default=datetime.utcnow)
    updated_at = DateTimeField(default=datetime.utcnow)

    meta = {
        "collection": "scan_jobs",
    }

    def save(self, *args, **kwargs):
        self.updated_at = datetime.utcnow()
        return super().save(*args, **kwargs)
