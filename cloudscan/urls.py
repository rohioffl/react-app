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
from .async_views import (
    UploadKeyView,
    StartGCPScanView,
    JobStatusView,
    JobHistoryView,
)
from .health import HealthCheckView

urlpatterns = [
    # Scan Endpoints
    path('scan/aws', ScanAWS.as_view(), name='scan-aws'),
    path('scan/gcp', scan_gcp, name='scan-gcp'),
    path('scan/gcp/', scan_gcp, name='scan-gcp-slash'),  # with trailing slash
    path('gcp/projects', upload_gcp_key, name='gcp-projects'),
    # Async project listing using Mongo persistence
    path('async/projects', UploadKeyView.as_view(), name='async-projects'),

    # Prowler Scan APIs
    # Async scan triggers
    path('scan/async/gcp/', prowler_scan_gcp, name='prowler-scan-gcp'),
    path('scan/async/aws/', prowler_scan_aws, name='prowler-scan-aws'),
    path('scan/async/gcp/db/', StartGCPScanView.as_view(), name='scan-gcp-db'),

    # Scan status (for progress polling)
    path('scan/status/<str:scan_id>/', scan_status, name='scan-status'),
    path('scan/status/db/<str:scan_id>/', JobStatusView.as_view(), name='scan-status-db'),

    # Scanlists
    path('scanlist/', api_prowler_scanlist, name='scanlist'),
    path('GCPscanlist/', api_prowler_gcp_scanlist, name='gcp-scanlist'),
    path('scanlist/db/', JobHistoryView.as_view(), name='scanlist-db'),

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

    # Health check
    path('health/', HealthCheckView.as_view(), name='health'),

    # Home
    path("", home, name="home"),
]
