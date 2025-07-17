from django.urls import path
from .views import (
    ScanAWS,
    ScanGCP,
    LatestAWSFindings,
    LatestGCPFindings,
    AWSFinding,
    GCPFinding,
    AWSScanHistory,
    GCPScanHistory,
    AWSScanFindingsExcel,
    GCPScanFindingsExcel,
)
from cloudscan import views

urlpatterns = [
    path('scan/aws', ScanAWS.as_view(), name='scan-aws'),
    path('scan/gcp', ScanGCP.as_view(), name='scan-gcp'),
    path('AWS_Scan', LatestAWSFindings.as_view(), name='aws-latest'),
    path('GCP_Scan', LatestGCPFindings.as_view(), name='gcp-latest'),
    path('AWSfinding/<str:scan_id>', AWSFinding.as_view(), name='aws-finding'),
    path('GCPfinding/<str:scan_id>', GCPFinding.as_view(), name='gcp-finding'),
    path('scanlist', AWSScanHistory.as_view(), name='aws-scan-list'),
    path('GCPscanlist', GCPScanHistory.as_view(), name='gcp-scan-list'),
    path('xls', AWSScanFindingsExcel.as_view(), name='aws-xls'),
    path('gcp-xls', GCPScanFindingsExcel.as_view(), name='gcp-xls'),
    path("", views.home, name="home"),
]
