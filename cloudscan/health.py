from rest_framework.views import APIView
from rest_framework.response import Response
from mongoengine.connection import get_db


class HealthCheckView(APIView):
    """Simple endpoint to verify MongoDB connectivity."""

    authentication_classes = []
    permission_classes = []

    def get(self, request):
        try:
            db = get_db()
            # Ping the database to ensure the connection is alive
            db.client.admin.command("ping")
            return Response({"mongodb": "connected"})
        except Exception as exc:
            return Response({"mongodb": "unavailable", "detail": str(exc)}, status=500)
