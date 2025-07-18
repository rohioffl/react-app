# cloudscan/views.py
"""Views for the CloudScan Django app."""

from django.http import JsonResponse, HttpResponse
from rest_framework.views import APIView
from rest_framework.response import Response
from bson import ObjectId
import mongoengine
import csv
import json
import os
import tempfile
from uuid import uuid4
from datetime import datetime

from .models import (
    AWSResult,
    GCPResult,
    AWSScan,
    GCPScan,
)
from .prowler_runner import run_prowler_aws, run_prowler_gcp

def aws_scan_history(request):
    # GET /AWS_Scan_History
    results = AWSResult.objects.only('id', 'date', 'provider', 'accountId', 'region').order_by('-date')
    data = [
        {
            "id": str(r.id),
            "date": r.date,
            "provider": r.provider,
            "accountId": r.accountId,
            "region": r.region
        }
        for r in results
    ]
    return JsonResponse({"success": True, "data": data})

def gcp_scan_history(request):
    # GET /GCP_Scan_History
    results = GCPResult.objects.only('id', 'date', 'provider', 'accountId', 'region').order_by('-date')
    data = [
        {
            "id": str(r.id),
            "date": r.date,
            "provider": r.provider,
            "accountId": r.accountId,
            "region": r.region
        }
        for r in results
    ]
    return JsonResponse({"success": True, "data": data})

def aws_findings(request, scan_id):
    # GET /AWSfinding/<id>
    try:
        result = AWSResult.objects.get(id=ObjectId(scan_id))
        findings = [f.to_mongo() for f in result.findings]
        return JsonResponse({"findings": findings})
    except mongoengine.DoesNotExist:
        return JsonResponse({"message": "No findings found for this ID"}, status=404)

def gcp_findings(request, scan_id):
    # GET /GCPfinding/<id>
    try:
        result = GCPResult.objects.get(id=ObjectId(scan_id))
        findings = [f.to_mongo() for f in result.findings]
        return JsonResponse({"findings": findings})
    except mongoengine.DoesNotExist:
        return JsonResponse({"message": "No findings found for this ID"}, status=404)


# ---------------------------------------------------------------------------
# Additional views required by cloudscan.urls
# ---------------------------------------------------------------------------

TEMP_KEYS = {}


def fetch_project_ids(key_path):
    """Return a list of accessible GCP project IDs for the given key file."""
    # A real implementation would call Google Cloud APIs.  This simple helper
    # just returns an empty list and is overridden in tests.
    return []


class ScanAWS(APIView):
    """Trigger an AWS scan using Prowler and store the results."""

    authentication_classes = []
    permission_classes = []

    def post(self, request):
        access_key = request.POST.get("accessKey")
        secret_key = request.POST.get("secretKey")
        region = request.POST.get("region", "all")
        checks = request.POST.get("checks")

        if not access_key or not secret_key:
            return Response({"error": "Missing credentials"}, status=400)

        json_path = run_prowler_aws(access_key, secret_key, region, checks=checks)

        with open(json_path, "r", encoding="utf-8") as fh:
            findings = json.load(fh)

        account_id = findings[0].get("AwsAccountId", "") if findings else ""
        reg = findings[0].get("Region", region) if findings else region

        scan = AWSScan(
            date=datetime.utcnow(),
            accountId=account_id,
            region=reg,
            findings=findings,
        )
        scan.save()

        return Response({"scan_id": str(scan.id), "findingsCount": len(findings)})


def _get_gcp_key_path(request):
    """Return path to GCP key file based on request or environment."""

    if request.FILES.get("keyFile"):
        uploaded = request.FILES["keyFile"]
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        for chunk in uploaded.chunks():
            tmp.write(chunk)
        tmp.close()
        return tmp.name, True

    key_id = request.POST.get("keyId")
    if key_id and key_id in TEMP_KEYS:
        path = TEMP_KEYS.pop(key_id)
        return path, True

    path = os.getenv("GCP_SERVICE_ACCOUNT_JSON_PATH")
    return path, False


def scan_gcp(request):
    checks = request.POST.get("checks")
    group = request.POST.get("group")
    project_id = request.POST.get("projectId") or os.getenv("GCP_PROJECT_ID")

    key_path, remove_key = _get_gcp_key_path(request)
    if not key_path:
        return JsonResponse({"error": "Missing GCP credentials"}, status=400)

    csv_path = run_prowler_gcp(key_path, project_id=project_id, checks=checks, group=group)

    findings = []
    with open(csv_path, newline="") as csvfile:
        reader = csv.DictReader(csvfile, delimiter=";")
        for row in reader:
            findings.append(row)
    if remove_key:
        os.remove(key_path)

    account_id = findings[0].get("ACCOUNT_UID", "") if findings else ""
    region = findings[0].get("REGION", "") if findings else ""

    scan = GCPScan(
        date=datetime.utcnow(),
        accountId=account_id,
        projectId=project_id,
        region=region,
        findings=findings,
    )
    scan.save()

    return JsonResponse({"scan_id": str(scan.id), "findingsCount": len(findings)})


# These async-style wrappers simply delegate to the synchronous views for this demo
def prowler_scan_gcp(request):
    return scan_gcp(request)


def prowler_scan_aws(request):
    view = ScanAWS.as_view()
    return view(request)


def scan_status(request, scan_id):  # noqa: D401 -- simple demo stub
    """Return placeholder status information for a scan."""
    return JsonResponse({"scan_id": scan_id, "status": "completed"})


def api_prowler_scanlist(request):  # noqa: D401 -- simple stub
    """Return an empty scan list."""
    return JsonResponse({"data": []})


def api_prowler_gcp_scanlist(request):  # noqa: D401 -- simple stub
    """Return an empty GCP scan list."""
    return JsonResponse({"data": []})


class LatestAWSFindings(APIView):
    def get(self, request):
        return aws_scan_history(request)


class LatestGCPFindings(APIView):
    def get(self, request):
        return gcp_scan_history(request)


class AWSFinding(APIView):
    def get(self, request, scan_id):
        return aws_findings(request, scan_id)


class GCPFinding(APIView):
    def get(self, request, scan_id):
        return gcp_findings(request, scan_id)


class AWSScanHistory(APIView):
    def get(self, request):
        return aws_scan_history(request)


class GCPScanHistory(APIView):
    def get(self, request):
        return gcp_scan_history(request)


class AWSScanFindingsExcel(APIView):
    def get(self, request):  # pragma: no cover - demo stub
        return Response(status=204)


class GCPScanFindingsExcel(APIView):
    def get(self, request):  # pragma: no cover - demo stub
        return Response(status=204)


def upload_gcp_key(request):
    file = request.FILES.get("keyFile")
    if not file:
        return JsonResponse({"error": "Missing GCP key file"}, status=400)

    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
        for chunk in file.chunks():
            tmp.write(chunk)
        key_path = tmp.name

    try:
        projects = fetch_project_ids(key_path)
    except Exception as exc:  # pylint: disable=broad-except
        projects = []
        warning = str(exc)
    else:
        warning = None

    key_id = str(uuid4())
    TEMP_KEYS[key_id] = key_path

    response = {"projects": projects, "keyId": key_id}
    if warning:
        response["warning"] = warning
    return JsonResponse(response)


def home(request):  # pragma: no cover - simple placeholder
    return HttpResponse("CloudScan API")

