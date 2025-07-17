from django.urls import path
from .views import ScanAWS, ScanGCP
from cloudscan import views

urlpatterns = [
    path('scan/aws', ScanAWS.as_view(), name='scan-aws'),
    path('scan/gcp', ScanGCP.as_view(), name='scan-gcp'),
    path("", views.home, name="home")
]
