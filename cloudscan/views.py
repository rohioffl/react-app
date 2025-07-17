import json
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .prowler_runner import run_prowler_aws, run_prowler_gcp
from .models import AWSScan, GCPScan
from datetime import datetime
import csv
import os


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
        
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def scan_gcp(request):
    if request.method != "POST":
        return JsonResponse({"error": "Only POST allowed"}, status=405)

    gcp_key_path = os.getenv("GCP_SERVICE_ACCOUNT_JSON_PATH")
    temp_key_created = False
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
        temp_key_created = True

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
        if temp_key_created:
            os.remove(gcp_key_path)


@csrf_exempt
def prowler_scan_gcp(request):
    """Handle POST to start a GCP scan via /api/prowler/scan/gcp/."""
    if request.method != "POST":
        return JsonResponse({"error": "Only POST allowed"}, status=405)

    # Here you could trigger the real scan asynchronously. For now just
    # acknowledge the request so the frontend knows the scan was started.
    return JsonResponse({"status": "Scan started"})

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

