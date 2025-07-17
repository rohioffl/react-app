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
        project_id = request.data.get("projectId") or os.getenv("GCP_PROJECT_ID")
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
        
from django.http import JsonResponse

def home(request):
    return JsonResponse({"message": "CloudScan API is running."})

