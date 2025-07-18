"""Example async scan API views using MongoEngine persistence.

These views run the scan in a background thread. For high volume systems,
consider using a task queue such as Celery instead of ``threading`` so jobs
survive process restarts and can be distributed across workers.
"""

import csv
import os
import tempfile
from uuid import uuid4
from threading import Thread
from datetime import datetime

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from .models import ScanJob, GCPScan
from .views import fetch_project_ids
from .prowler_runner import run_prowler_gcp


def _cleanup(path):
    """Remove a temporary file if it exists."""
    if path and os.path.exists(path):
        os.remove(path)


class UploadKeyView(APIView):
    """Accept a key file and return accessible projects with a keyId."""

    def post(self, request):
        file = request.FILES.get("keyFile")
        if not file:
            return Response({"error": "Missing GCP key file"}, status=400)

        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
            for chunk in file.chunks():
                tmp.write(chunk)
            key_path = tmp.name

        try:
            projects = fetch_project_ids(key_path)
        except Exception as exc:  # pylint: disable=broad-except
            # propagate friendly message but still return keyId
            projects = []
            error = str(exc)
        else:
            error = None

        key_id = str(uuid4())
        ScanJob(
            scan_id=key_id,
            provider="GCP",
            status="uploaded",
            result={"key_path": key_path},
        ).save()

        response = {"projects": projects, "keyId": key_id}
        if error:
            response["warning"] = error
        return Response(response)


class StartGCPScanView(APIView):
    """Start an asynchronous GCP scan."""

    def post(self, request):
        key_id = request.data.get("keyId")
        project_id = request.data.get("projectId")
        checks = request.data.get("checks")
        if not key_id or not project_id:
            return Response({"error": "keyId and projectId required"}, status=400)

        # Retrieve and remove the uploaded key path stored in ScanJob
        try:
            key_job = ScanJob.objects.get(scan_id=key_id)
        except ScanJob.DoesNotExist:
            return Response({"error": "Invalid keyId"}, status=400)

        key_path = key_job.result.get("key_path")
        if not key_path:
            return Response({"error": "Key file missing"}, status=400)

        scan_id = str(uuid4())
        job = ScanJob(
            scan_id=scan_id,
            provider="GCP",
            projectId=project_id,
            status="running",
        )
        job.save()

        def run():
            try:
                job.update(status="running", progress=10)
                csv_path = run_prowler_gcp(key_path, project_id=project_id, checks=checks)
                job.update(progress=80)
                findings = []
                with open(csv_path, newline="") as csvfile:
                    reader = csv.DictReader(csvfile, delimiter=";")
                    for row in reader:
                        findings.append(row)
                scan = GCPScan(
                    date=datetime.utcnow(),
                    provider="GCP",
                    accountId=findings[0].get("ACCOUNT_UID", "unknown"),
                    projectId=project_id,
                    region=findings[0].get("REGION", "global"),
                    findings=findings,
                )
                scan.save()
                job.update(progress=100, status="completed", result={"scanId": str(scan.id), "findingsCount": len(findings)})
            except Exception as exc:  # pylint: disable=broad-except
                job.update(progress=100, status="error", result={"error": str(exc)})
            finally:
                _cleanup(key_path)

        Thread(target=run, daemon=True).start()
        return Response({"scan_id": scan_id})


class JobStatusView(APIView):
    """Return progress info for a scan."""

    def get(self, request, scan_id):
        try:
            job = ScanJob.objects.get(scan_id=scan_id)
        except ScanJob.DoesNotExist:
            return Response({"error": "Not found"}, status=404)

        data = {
            "status": job.status,
            "progress": job.progress,
            "result": job.result,
        }
        return Response(data)


class JobHistoryView(APIView):
    """Return basic info for past scans."""

    def get(self, request):
        scans = ScanJob.objects.order_by("-created_at")
        data = [
            {
                "scan_id": s.scan_id,
                "provider": s.provider,
                "projectId": s.projectId,
                "status": s.status,
                "created_at": s.created_at,
            }
            for s in scans
        ]
        return Response({"data": data})

