# project/urls.py
from django.urls import path, include
from django.contrib import admin

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/prowler/', include('cloudscan.urls')),   # <--- ADD PREFIX HERE
]
