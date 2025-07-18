# cloudscan/models.py
from mongoengine import Document, StringField, DateTimeField, ListField, EmbeddedDocument, EmbeddedDocumentField, DictField, BooleanField, IntField

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
