from django.test import TestCase, Client
from django.core.files.uploadedfile import SimpleUploadedFile
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
        import mongomock
        connect("testdb", host="mongodb://localhost", mongo_client_class=mongomock.MongoClient)
        os.environ.setdefault("DJANGO_SECRET_KEY", "testing-secret")

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
                "/api/prowler/scan/aws",
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
                tmp_csv,
                fieldnames=["ACCOUNT_UID", "REGION", "PROJECT_ID"],
                delimiter=";",
            )
            writer.writeheader()
            writer.writerow(
                {"ACCOUNT_UID": "gcp123", "REGION": "us-central1", "PROJECT_ID": "proj"}
            )
            csv_path = tmp_csv.name

        with patch("cloudscan.views.run_prowler_gcp", return_value=csv_path):
            with patch.dict(
                os.environ,
                {"GCP_SERVICE_ACCOUNT_JSON_PATH": "/tmp/key.json"},
            ):
                resp = self.client.post("/api/prowler/scan/gcp", {"projectId": "proj"})

        os.remove(csv_path)

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(GCPScan.objects.count(), 1)
        scan = GCPScan.objects.first()
        self.assertEqual(scan.accountId, "gcp123")
        self.assertEqual(scan.projectId, "proj")

    def test_scan_aws_with_checks(self):
        """POST /scan/aws should pass checks to the runner."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp_json:
            json.dump([{"AwsAccountId": "123"}], tmp_json)
            json_path = tmp_json.name

        with patch("cloudscan.views.run_prowler_aws", return_value=json_path) as mock_run:
            resp = self.client.post(
                "/api/prowler/scan/aws",
                {
                    "accessKey": "AKIA...",
                    "secretKey": "secret",
                    "checks": "check1",
                },
            )

        os.remove(json_path)

        self.assertEqual(resp.status_code, 200)
        mock_run.assert_called_with("AKIA...", "secret", "all", checks="check1")

    def test_scan_gcp_with_checks_and_group(self):
        """POST /scan/gcp should pass checks and group to the runner."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as tmp_csv:
            writer = csv.DictWriter(tmp_csv, fieldnames=["ACCOUNT_UID", "REGION"], delimiter=";")
            writer.writeheader()
            writer.writerow({"ACCOUNT_UID": "id", "REGION": "region"})
            csv_path = tmp_csv.name

        with patch("cloudscan.views.run_prowler_gcp", return_value=csv_path) as mock_run:
            with patch.dict(os.environ, {"GCP_SERVICE_ACCOUNT_JSON_PATH": "/tmp/key.json"}):
                resp = self.client.post(
                    "/api/prowler/scan/gcp",
                    {"checks": "check2", "group": "group2"},
                )

        os.remove(csv_path)

        self.assertEqual(resp.status_code, 200)
        mock_run.assert_called_with(
            "/tmp/key.json", checks="check2", group="group2", project_id=None
        )

    def test_scan_gcp_with_project_id(self):
        """POST /scan/gcp should pass projectId to the runner."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as tmp_csv:
            writer = csv.DictWriter(tmp_csv, fieldnames=["ACCOUNT_UID", "REGION"], delimiter=";")
            writer.writeheader()
            writer.writerow({"ACCOUNT_UID": "id", "REGION": "region"})
            csv_path = tmp_csv.name

        with patch("cloudscan.views.run_prowler_gcp", return_value=csv_path) as mock_run:
            with patch.dict(os.environ, {"GCP_SERVICE_ACCOUNT_JSON_PATH": "/tmp/key.json"}):
                resp = self.client.post("/api/prowler/scan/gcp", {"projectId": "proj-1"})

        os.remove(csv_path)

        self.assertEqual(resp.status_code, 200)
        mock_run.assert_called_with("/tmp/key.json", checks=None, group=None, project_id="proj-1")

    def test_scan_gcp_project_id_env(self):
        """If projectId not in request, value from env is used."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as tmp_csv:
            writer = csv.DictWriter(tmp_csv, fieldnames=["ACCOUNT_UID", "REGION"], delimiter=";")
            writer.writeheader()
            writer.writerow({"ACCOUNT_UID": "id", "REGION": "region"})
            csv_path = tmp_csv.name

        with patch("cloudscan.views.run_prowler_gcp", return_value=csv_path) as mock_run:
            with patch.dict(os.environ, {
                "GCP_SERVICE_ACCOUNT_JSON_PATH": "/tmp/key.json",
                "GCP_PROJECT_ID": "env-proj",
            }):
                resp = self.client.post("/api/prowler/scan/gcp")

        os.remove(csv_path)

        self.assertEqual(resp.status_code, 200)
        mock_run.assert_called_with("/tmp/key.json", checks=None, group=None, project_id="env-proj")

    def test_scan_gcp_temp_key_file_removed(self):
        """Temporary key file uploaded should be removed after scan."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as tmp_csv:
            writer = csv.DictWriter(tmp_csv, fieldnames=["ACCOUNT_UID", "REGION"], delimiter=";")
            writer.writeheader()
            writer.writerow({"ACCOUNT_UID": "id", "REGION": "region"})
            csv_path = tmp_csv.name

        captured = {}

        def fake_run(key_path, checks=None, group=None, project_id=None):
            captured['path'] = key_path
            self.assertTrue(os.path.exists(key_path))
            return csv_path

        with patch("cloudscan.views.run_prowler_gcp", side_effect=fake_run):
            with patch("os.remove") as mock_remove:
                uploaded = SimpleUploadedFile("key.json", b"{}", content_type="application/json")
                resp = self.client.post("/api/prowler/scan/gcp", {"keyFile": uploaded})

        os.remove(csv_path)

        self.assertEqual(resp.status_code, 200)
        mock_remove.assert_called_once_with(captured['path'])

    def test_scan_gcp_env_key_not_removed(self):
        """Key path from env should not be deleted."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as tmp_csv:
            writer = csv.DictWriter(tmp_csv, fieldnames=["ACCOUNT_UID", "REGION"], delimiter=";")
            writer.writeheader()
            writer.writerow({"ACCOUNT_UID": "id", "REGION": "region"})
            csv_path = tmp_csv.name

        with patch("cloudscan.views.run_prowler_gcp", return_value=csv_path):
            with patch.dict(os.environ, {"GCP_SERVICE_ACCOUNT_JSON_PATH": "/tmp/key.json"}):
                with patch("os.remove") as mock_remove:
                    resp = self.client.post("/api/prowler/scan/gcp")

        os.remove(csv_path)

        self.assertEqual(resp.status_code, 200)
        mock_remove.assert_not_called()

    def test_upload_gcp_key_returns_projects(self):
        """Uploading a key should return projects and a keyId."""
        uploaded = SimpleUploadedFile("key.json", b"{}", content_type="application/json")
        with patch("cloudscan.views.fetch_project_ids", return_value=["proj1", "proj2"]):
            resp = self.client.post("/api/prowler/gcp/projects", {"keyFile": uploaded})

        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.content)
        self.assertEqual(data["projects"], ["proj1", "proj2"])
        self.assertIn("keyId", data)

    def test_upload_gcp_key_handles_project_list_error(self):
        """Even if listing projects fails, a keyId should be returned."""
        uploaded = SimpleUploadedFile("key.json", b"{}", content_type="application/json")
        with patch("cloudscan.views.fetch_project_ids", side_effect=Exception("bad")):
            resp = self.client.post("/api/prowler/gcp/projects", {"keyFile": uploaded})

        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.content)
        self.assertEqual(data["projects"], [])
        self.assertIn("keyId", data)

    def test_scan_gcp_with_key_id(self):
        """/scan/gcp should accept keyId referencing uploaded file."""
        uploaded = SimpleUploadedFile("key.json", b"{}", content_type="application/json")
        with patch("cloudscan.views.fetch_project_ids", return_value=["proj"]):
            resp = self.client.post("/api/prowler/gcp/projects", {"keyFile": uploaded})
            key_id = json.loads(resp.content)["keyId"]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as tmp_csv:
            writer = csv.DictWriter(tmp_csv, fieldnames=["ACCOUNT_UID", "REGION"], delimiter=";")
            writer.writeheader()
            writer.writerow({"ACCOUNT_UID": "id", "REGION": "region"})
            csv_path = tmp_csv.name

        captured = {}

        def fake_run(path, checks=None, group=None, project_id=None):
            captured["path"] = path
            return csv_path

        with patch("cloudscan.views.run_prowler_gcp", side_effect=fake_run):
            resp = self.client.post("/api/prowler/scan/gcp", {"keyId": key_id, "projectId": "proj"})

        os.remove(csv_path)

        self.assertEqual(resp.status_code, 200)
        # path from TEMP_KEYS should be used and removed after
        self.assertFalse(os.path.exists(captured["path"]))
