from mongoengine import Document, StringField, DateTimeField, DictField, ListField

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
    region = StringField()
    findings = ListField(DictField())
