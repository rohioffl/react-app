from django.test import TestCase, Client
from unittest.mock import patch
from mongoengine import connect, disconnect

from .models import AWSScan, GCPScan

import os
import json
import csv
import tempfile


class ScanViewTests(TestCase):
    """Integration tests for the scan views using MongoDB."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # Use an in-memory MongoDB via mongomock
        connect("testdb", host="mongomock://localhost")

    @classmethod
    def tearDownClass(cls):
        disconnect()
        super().tearDownClass()

    def setUp(self):
        AWSScan.drop_collection()
        GCPScan.drop_collection()
        self.client = Client()

    def test_scan_aws_creates_entry(self):
        """POST /scan/aws should create an AWSScan document."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp_json:
            json.dump([{"AwsAccountId": "123456789012"}], tmp_json)
            json_path = tmp_json.name

        with patch("cloudscan.views.run_prowler_aws", return_value=json_path):
            resp = self.client.post(
                "/scan/aws",
                {
                    "accessKey": "AKIA...",
                    "secretKey": "secret",
                    "region": "us-east-1",
                },
            )

        os.remove(json_path)

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(AWSScan.objects.count(), 1)
        scan = AWSScan.objects.first()
        self.assertEqual(scan.accountId, "123456789012")

    def test_scan_gcp_creates_entry(self):
        """POST /scan/gcp should create a GCPScan document."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as tmp_csv:
            writer = csv.DictWriter(
                tmp_csv, fieldnames=["ACCOUNT_UID", "REGION"], delimiter=";"
            )
            writer.writeheader()
            writer.writerow({"ACCOUNT_UID": "gcp123", "REGION": "us-central1"})
            csv_path = tmp_csv.name

        with patch("cloudscan.views.run_prowler_gcp", return_value=csv_path):
            with patch.dict(os.environ, {"GCP_SERVICE_ACCOUNT_JSON_PATH": "/tmp/key.json"}):
                resp = self.client.post("/scan/gcp")

        os.remove(csv_path)

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(GCPScan.objects.count(), 1)
        scan = GCPScan.objects.first()
        self.assertEqual(scan.accountId, "gcp123")
