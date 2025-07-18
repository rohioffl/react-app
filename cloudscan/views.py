import json
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .prowler_runner import run_prowler_aws, run_prowler_gcp
from .models import AWSScan, GCPScan
from datetime import datetime
import csv
import os
import tempfile
import subprocess
from uuid import uuid4
from threading import Thread
from time import sleep
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

# In-memory store for async scan progress and results
SCAN_JOBS = {}
# Temporary storage mapping key IDs to uploaded service account files
TEMP_KEYS = {}

def fetch_project_ids(key_path):
    """Return a list of accessible GCP project IDs using the given service account."""
    try:
        from google.cloud import resourcemanager_v3
        from google.oauth2 import service_account

        creds = service_account.Credentials.from_service_account_file(key_path)
        client = resourcemanager_v3.ProjectsClient(credentials=creds)
        # Try both ways:
        projects = client.list_projects()  # Try with NO parent
        # projects = client.list_projects(parent="organizations/XYZ")  # Only if you know the org ID and format
        return [p.project_id for p in projects if p.state.name == "ACTIVE"]
    except Exception as e:
        print(f"DEBUG ERROR: {e}")
        raise Exception(
            "Could not list projects with the uploaded key. "
            "Ensure that:\n"
            " - The service account has 'roles/browser' or 'roles/viewer' at the org or folder level\n"
            " - Cloud Resource Manager API is enabled for all relevant projects\n"
            f"Details: {e}"
        )



class ScanAWS(APIView):
    def post(self, request):
        access_key = os.getenv("AWS_ACCESS_KEY_ID") or request.data.get("accessKey")
        secret_key = os.getenv("AWS_SECRET_ACCESS_KEY") or request.data.get("secretKey")
        region = request.data.get("region", "all")
        checks = request.data.get("checks")
        if not access_key or not secret_key:
            return Response({"error": "Missing AWS credentials"}, status=400)
        try:
            json_path = run_prowler_aws(access_key, secret_key, region, checks=checks)
            with open(json_path) as f:
                findings = json.load(f)
            scan = AWSScan(
                date=datetime.now(),
                provider="AWS",
                accountId=findings[0].get("AwsAccountId", "unknown"),
                region=region,
                findings=findings
            )
            scan.save()
            return Response({"message": "✅ AWS Scan completed", "findingsCount": len(findings), "scanId": str(scan.id)})
        except Exception as e:
            return Response({"error": str(e)}, status=500)

import tempfile

class ScanGCP(APIView):
    def post(self, request):
        gcp_key_path = os.getenv("GCP_SERVICE_ACCOUNT_JSON_PATH")
        temp_key_created = False
        project_id = os.getenv("GCP_PROJECT_ID") or request.data.get("projectId")
        checks = request.data.get("checks")
        group = request.data.get("group")
        if not gcp_key_path:
            file = request.FILES.get("keyFile")
            if not file:
                return Response({"error": "Missing GCP key file"}, status=400)
            with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as temp_key:
                for chunk in file.chunks():
                    temp_key.write(chunk)
                gcp_key_path = temp_key.name
            temp_key_created = True

        try:
            csv_path = run_prowler_gcp(
                gcp_key_path, checks=checks, group=group, project_id=project_id
            )
            findings = []
            with open(csv_path, newline='') as csvfile:
                reader = csv.DictReader(csvfile, delimiter=';')
                for row in reader:
                    findings.append(row)
            scan = GCPScan(
                date=datetime.now(),
                provider="GCP",
                accountId=findings[0].get("ACCOUNT_UID", "unknown"),
                projectId=findings[0].get("PROJECT_ID", project_id or "unknown"),
                region=findings[0].get("REGION", "global"),
                findings=findings
            )
            scan.save()
            return Response({"message": "✅ GCP Scan completed", "findingsCount": len(findings), "scanId": str(scan.id)})
        except Exception as e:
            return Response({"error": str(e)}, status=500)
        finally:
            if temp_key_created:
                os.remove(gcp_key_path)


@csrf_exempt
def upload_gcp_key(request):
    """Handle service account key upload and return accessible projects."""
    if request.method != "POST":
        return JsonResponse({"error": "Only POST allowed"}, status=405)

    file = request.FILES.get("keyFile")
    if not file:
        return JsonResponse({"error": "Missing GCP key file"}, status=400)

    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as temp_key:
        for chunk in file.chunks():
            temp_key.write(chunk)
        key_path = temp_key.name

    try:
        projects = fetch_project_ids(key_path)
    except Exception as e:
        os.remove(key_path)
        return JsonResponse({"error": str(e)}, status=500)

    key_id = str(uuid4())
    TEMP_KEYS[key_id] = key_path
    return JsonResponse({"projects": projects, "keyId": key_id})
        


@csrf_exempt
def scan_gcp(request):
    if request.method != "POST":
        return JsonResponse({"error": "Only POST allowed"}, status=405)

    key_id = request.POST.get("keyId")
    gcp_key_path = TEMP_KEYS.get(key_id) if key_id else os.getenv("GCP_SERVICE_ACCOUNT_JSON_PATH")
    remove_after = False
    project_id = os.getenv("GCP_PROJECT_ID") or request.POST.get("projectId")
    checks = request.POST.get("checks")
    group = request.POST.get("group")

    if not gcp_key_path:
        file = request.FILES.get("keyFile")
        if not file:
            return JsonResponse({"error": "Missing GCP key file"}, status=400)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as temp_key:
            for chunk in file.chunks():
                temp_key.write(chunk)
            gcp_key_path = temp_key.name
        remove_after = True
    elif key_id:
        remove_after = True

    try:
        csv_path = run_prowler_gcp(
            gcp_key_path, checks=checks, group=group, project_id=project_id
        )
        findings = []
        with open(csv_path, newline="") as csvfile:
            reader = csv.DictReader(csvfile, delimiter=";")
            for row in reader:
                findings.append(row)
        scan = GCPScan(
            date=datetime.now(),
            provider="GCP",
            accountId=findings[0].get("ACCOUNT_UID", "unknown"),
            projectId=findings[0].get("PROJECT_ID", project_id or "unknown"),
            region=findings[0].get("REGION", "global"),
            findings=findings,
        )
        scan.save()
        return JsonResponse(
            {
                "message": "✅ GCP Scan completed",
                "findingsCount": len(findings),
                "scanId": str(scan.id),
            }
        )
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)
    finally:
        if remove_after and gcp_key_path:
            os.remove(gcp_key_path)
            if key_id:
                TEMP_KEYS.pop(key_id, None)



def home(request):
    return JsonResponse({"message": "CloudScan API is running."})

# Additional API views used by the React frontend

class LatestAWSFindings(APIView):
    """Return findings from the most recent AWS scan."""

    def get(self, request):
        scan = AWSScan.objects.order_by('-date').first()
        if not scan:
            return Response({"findings": []})
        return Response({"findings": scan.findings})


class LatestGCPFindings(APIView):
    """Return findings from the most recent GCP scan."""

    def get(self, request):
        scan = GCPScan.objects.order_by('-date').first()
        if not scan:
            return Response({"findings": []})
        return Response({"findings": scan.findings})


class AWSFinding(APIView):
    """Return findings for a specific AWS scan."""

    def get(self, request, scan_id):
        try:
            scan = AWSScan.objects.get(id=scan_id)
        except AWSScan.DoesNotExist:
            return Response({"error": "Scan not found"}, status=404)
        return Response({"findings": scan.findings})


class GCPFinding(APIView):
    """Return findings for a specific GCP scan."""

    def get(self, request, scan_id):
        try:
            scan = GCPScan.objects.get(id=scan_id)
        except GCPScan.DoesNotExist:
            return Response({"error": "Scan not found"}, status=404)
        return Response({"findings": scan.findings})


class AWSScanHistory(APIView):
    """Return a list of all AWS scans with basic info."""

    def get(self, request):
        scans = AWSScan.objects.order_by('-date')
        data = [
            {
                "_id": str(scan.id),
                "date": scan.date,
                "provider": scan.provider,
                "region": scan.region,
                "accountId": scan.accountId,
            }
            for scan in scans
        ]
        return Response({"data": data})


class GCPScanHistory(APIView):
    """Return a list of all GCP scans with basic info."""

    def get(self, request):
        scans = GCPScan.objects.order_by('-date')
        data = [
            {
                "_id": str(scan.id),
                "date": scan.date,
                "provider": scan.provider,
                "region": scan.region,
                "accountId": scan.accountId,
                "projectId": scan.projectId,
            }
            for scan in scans
        ]
        return Response({"data": data})


class AWSScanFindingsExcel(APIView):
    """Return findings for an AWS scan (used for Excel export)."""

    def post(self, request):
        scan_id = request.data.get("id")
        if not scan_id:
            return Response({"error": "Missing id"}, status=400)
        try:
            scan = AWSScan.objects.get(id=scan_id)
        except AWSScan.DoesNotExist:
            return Response({"error": "Scan not found"}, status=404)
        return Response({"findings": scan.findings})


class GCPScanFindingsExcel(APIView):
    """Return findings for a GCP scan (used for Excel export)."""

    def post(self, request):
        scan_id = request.data.get("id")
        if not scan_id:
            return Response({"error": "Missing id"}, status=400)
        try:
            scan = GCPScan.objects.get(id=scan_id)
        except GCPScan.DoesNotExist:
            return Response({"error": "Scan not found"}, status=404)
        return Response({"findings": scan.findings})

# --- Async scan helpers and API endpoints ---

def _simulate_progress(scan_id):
    """Simulate progress updates for demonstration purposes."""
    for i in range(1, 11):
        SCAN_JOBS[scan_id]["progress"] = i * 10
        sleep(0.5)
    SCAN_JOBS[scan_id]["result"] = {"status": "completed"}


@csrf_exempt
def prowler_scan_aws(request):
    """Start an async AWS scan and return a scan_id."""
    if request.method != "POST":
        return JsonResponse({"error": "Only POST allowed"}, status=405)

    scan_id = str(uuid4())
    SCAN_JOBS[scan_id] = {"progress": 0}
    Thread(target=_simulate_progress, args=(scan_id,), daemon=True).start()
    return JsonResponse({"scan_id": scan_id})


@csrf_exempt
def prowler_scan_gcp(request):
    """Start an async GCP scan and return a scan_id."""
    if request.method != "POST":
        return JsonResponse({"error": "Only POST allowed"}, status=405)

    key_id = request.POST.get("keyId")
    project_id = request.POST.get("projectId")
    if not key_id or not project_id:
        return JsonResponse({"error": "Missing keyId or projectId"}, status=400)

    key_path = TEMP_KEYS.get(key_id)
    if not key_path:
        return JsonResponse({"error": "Invalid keyId"}, status=400)

    scan_id = str(uuid4())
    SCAN_JOBS[scan_id] = {"progress": 0}

    def run_scan():
        progress_thread = Thread(target=_simulate_progress, args=(scan_id,), daemon=True)
        progress_thread.start()
        try:
            csv_path = run_prowler_gcp(key_path, project_id=project_id)
            findings = []
            with open(csv_path, newline="") as csvfile:
                reader = csv.DictReader(csvfile, delimiter=";")
                for row in reader:
                    findings.append(row)
            scan = GCPScan(
                date=datetime.now(),
                provider="GCP",
                accountId=findings[0].get("ACCOUNT_UID", "unknown"),
                projectId=project_id,
                region=findings[0].get("REGION", "global"),
                findings=findings,
            )
            scan.save()
            SCAN_JOBS[scan_id]["result"] = {"scanId": str(scan.id), "findingsCount": len(findings)}
        except Exception as e:
            SCAN_JOBS[scan_id]["result"] = {"error": str(e)}
        finally:
            os.remove(key_path)
            TEMP_KEYS.pop(key_id, None)

    Thread(target=run_scan, daemon=True).start()
    return JsonResponse({"scan_id": scan_id})


def scan_status(request, scan_id):
    """Return progress info for a running scan."""
    job = SCAN_JOBS.get(scan_id)
    if not job:
        return JsonResponse({"error": "Not found"}, status=404)
    return JsonResponse({"progress": job.get("progress", 0), "result": job.get("result")})


def api_prowler_scanlist(request):
    """Dummy endpoint returning an empty scan list."""
    return JsonResponse({"scans": []})


def api_prowler_gcp_scanlist(request):
    """Dummy endpoint returning an empty GCP scan list."""
    return JsonResponse({"scans": []})

