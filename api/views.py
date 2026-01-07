from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from rest_framework.views import APIView


class TestView(APIView):
    def get(self, request):
        print("Hi")
        return Response({"message": "It is working!!!"})
