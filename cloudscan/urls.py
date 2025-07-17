from django.urls import path
from .views import (
    ScanAWS,
    scan_gcp,
    prowler_scan_gcp,
    prowler_scan_aws,
    scan_status,
    api_prowler_scanlist,
    api_prowler_gcp_scanlist,
    LatestAWSFindings,
    LatestGCPFindings,
    AWSFinding,
    GCPFinding,
    AWSScanHistory,
    GCPScanHistory,
    AWSScanFindingsExcel,
    GCPScanFindingsExcel,
    upload_gcp_key,
    home,
)

urlpatterns = [
    # Scan Endpoints
    path('scan/aws', ScanAWS.as_view(), name='scan-aws'),
    path('scan/gcp', scan_gcp, name='scan-gcp'),
    path('scan/gcp/', scan_gcp, name='scan-gcp-slash'),  # with trailing slash
    path('gcp/projects', upload_gcp_key, name='gcp-projects'),

    # Prowler Scan APIs
    path('scan/gcp/', prowler_scan_gcp, name='prowler-scan-gcp'),  # For POST scan trigger
    path('scan/aws/', prowler_scan_aws, name='prowler-scan-aws'),  # For POST scan trigger

    # Scan status (for progress polling)
    path('scan/status/<str:scan_id>/', scan_status, name='scan-status'),

    # Scanlists
    path('scanlist/', api_prowler_scanlist, name='scanlist'),
    path('GCPscanlist/', api_prowler_gcp_scanlist, name='gcp-scanlist'),

    # Findings & History
    path('AWS_Scan/', LatestAWSFindings.as_view(), name='aws-latest'),
    path('GCP_Scan/', LatestGCPFindings.as_view(), name='gcp-latest'),
    path('AWSfinding/<str:scan_id>/', AWSFinding.as_view(), name='aws-finding'),
    path('GCPfinding/<str:scan_id>/', GCPFinding.as_view(), name='gcp-finding'),
    path('scanlist/history/', AWSScanHistory.as_view(), name='aws-scan-history'),
    path('GCPscanlist/history/', GCPScanHistory.as_view(), name='gcp-scan-history'),

    # Excel downloads
    path('xls/', AWSScanFindingsExcel.as_view(), name='aws-xls'),
    path('gcp-xls/', GCPScanFindingsExcel.as_view(), name='gcp-xls'),

    # Home
    path("", home, name="home"),
]
