# cloudscan/views.py
from .models import AWSResult, GCPResult
from django.http import JsonResponse
from bson import ObjectId
import mongoengine

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
