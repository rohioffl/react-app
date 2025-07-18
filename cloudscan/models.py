# cloudscan/models.py
from mongoengine import (
    Document,
    StringField,
    DateTimeField,
    ListField,
    EmbeddedDocument,
    EmbeddedDocumentField,
    DictField,
    BooleanField,
    IntField,
)
from datetime import datetime

class AWSSingleFinding(EmbeddedDocument):
    Id = StringField()
    Title = StringField()
    Description = StringField()
    AwsAccountId = StringField()
    Severity = DictField()
    Types = ListField(StringField())
    Resources = ListField(DictField())
    Compliance = DictField()
    CreatedAt = StringField()
    UpdatedAt = StringField()
    FirstObservedAt = StringField()
    Remediation = DictField()
    RecordState = StringField()

class AWSResult(Document):
    date = DateTimeField()
    provider = StringField()
    accountId = StringField()
    region = StringField()
    findings = ListField(EmbeddedDocumentField(AWSSingleFinding))
    meta = {'collection': 'awsresults'}

class GCPSingleFinding(EmbeddedDocument):
    AUTH_METHOD = StringField()
    TIMESTAMP = DateTimeField()
    ACCOUNT_UID = StringField()
    ACCOUNT_NAME = StringField()
    FINDING_UID = StringField()
    PROVIDER = StringField()
    CHECK_ID = StringField()
    CHECK_TITLE = StringField()
    CHECK_TYPE = StringField()
    STATUS = StringField()
    STATUS_EXTENDED = StringField()
    MUTED = BooleanField()
    SERVICE_NAME = StringField()
    SUBSERVICE_NAME = StringField()
    SEVERITY = StringField()
    RESOURCE_TYPE = StringField()
    RESOURCE_UID = StringField()
    RESOURCE_NAME = StringField()
    REGION = StringField()
    DESCRIPTION = StringField()
    RISK = StringField()
    RELATED_URL = StringField()
    REMEDIATION_RECOMMENDATION_TEXT = StringField()
    REMEDIATION_RECOMMENDATION_URL = StringField()
    REMEDIATION_CODE_CLI = StringField()
    COMPLIANCE = StringField()
    NOTES = StringField()
    PROWLER_VERSION = StringField()

class GCPResult(Document):
    date = DateTimeField()
    provider = StringField(default='GCP')
    accountId = StringField()
    region = StringField()
    findings = ListField(EmbeddedDocumentField(GCPSingleFinding))
    meta = {'collection': 'gcpresults'}


class AWSScan(Document):
    """Simplified document storing raw AWS scan findings."""

    provider = StringField(default="AWS")
    date = DateTimeField()
    accountId = StringField()
    region = StringField()
    findings = ListField(DictField())


class GCPScan(Document):
    """Simplified document storing raw GCP scan findings."""

    provider = StringField(default="GCP")
    date = DateTimeField()
    accountId = StringField()
    projectId = StringField()
    region = StringField()
    findings = ListField(DictField())


class ScanJob(Document):
    """Track async scan progress for the example async workflow."""

    scan_id = StringField(primary_key=True)
    provider = StringField(required=True)
    projectId = StringField()
    status = StringField(default="queued")
    progress = IntField(default=0)
    result = DictField()
    created_at = DateTimeField(default=datetime.utcnow)
    updated_at = DateTimeField(default=datetime.utcnow)

    meta = {"collection": "scan_jobs"}

    def save(self, *args, **kwargs):
        self.updated_at = datetime.utcnow()
        return super().save(*args, **kwargs)
