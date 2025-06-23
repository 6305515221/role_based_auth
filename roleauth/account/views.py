from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from django.contrib.auth import authenticate, login,logout
from .serializers import *
from .models import CustomUser
import logging
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from django.core.cache import cache

# You can move these to settings.py for security
ADMIN_SECRET = 'admin@123'
SUPERADMIN_SECRET = 'super@123'

logger = logging.getLogger('account')


class SignupAPIView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = SignupSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response({
                "message": "User created successfully",
                "username": user.username,
                "role": user.role
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class LoginAPIView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data.get('username')
            password = serializer.validated_data.get('password')
            selected_role = serializer.validated_data.get('role', 'User')
            secret_key = serializer.validated_data.get('secret_key', '')

            user = authenticate(username=username, password=password)
            if user:
                # Validate secret keys for elevated roles
                if selected_role == 'Admin' and secret_key != ADMIN_SECRET:
                    return Response({'error': 'Invalid Admin secret key'}, status=status.HTTP_403_FORBIDDEN)
                if selected_role == 'SuperAdmin' and secret_key != SUPERADMIN_SECRET:
                    return Response({'error': 'Invalid SuperAdmin secret key'}, status=status.HTTP_403_FORBIDDEN)

                login(request, user)

                # If selected role is Admin or SuperAdmin and secret key is valid, update it
                if selected_role in ['Admin', 'SuperAdmin']:
                    user.role = selected_role
                    user.save()

                return Response({
                    'message': 'Login successful',
                    'username': user.username,
                    'role': user.role
                }, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Custom permission classes
class IsUser(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'User'

class IsAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'Admin'

class IsSuperAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'SuperAdmin'


class UserPageView(APIView):
    permission_classes = [IsAuthenticated, IsUser]

    # def get(self, request):
    #     return Response({"message": "Welcome User!"})
    def get(self,request):
        serializer_list = UserSerializer(request.user)
        return Response(serializer_list.data, status=status.HTTP_200_OK)


class AdminPageView(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]

    # def get(self, request):
    #     return Response({"message": "Welcome Admin!"})
    # def get(self,request):
    #     data=CustomUser.objects.filter(role='Admin')
    #     # serializer_list = adminSerializer(request.user)
    #     serializer_list = adminSerializer(data, many=True)
    #     return Response(serializer_list.data, status=status.HTTP_200_OK)

    # def get(self, request):
    #     try:
    #         logger.info(f"AdminPageView accessed by: {request.user.username}")

    #         data = CustomUser.objects.filter(role='Admin')
    #         admin_count = data.count()

    #         if admin_count == 0:
    #             logger.warning("No admin users found in the database.")

    #         serializer_list = adminSerializer(data, many=True)
    #         logger.debug(f"Serialized {admin_count} admin records successfully by {request.user.username}")

    #         return Response(serializer_list.data, status=status.HTTP_200_OK)

    #     except Exception as e:
    #         logger.error("Unexpected exception occurred in AdminPageView", exc_info=True)
    #         return Response(
    #             {"error": "Internal Server Error"},
    #             status=status.HTTP_500_INTERNAL_SERVER_ERROR
    #         )

    def get(self, request):
        # Check Redis cache
        cached_data = cache.get('admin_users_list')
        if cached_data:
            return Response(cached_data, status=status.HTTP_200_OK)

        # If not cached, fetch from DB
        data = CustomUser.objects.filter(role='Admin')
        serializer_list = adminSerializer(data, many=True)

        # Cache the result for 5 minutes (300 seconds)
        cache.set('admin_users_list', serializer_list.data, timeout=300)

        return Response(serializer_list.data, status=status.HTTP_200_OK)

class SuperAdminPageView(APIView):
    permission_classes = [IsAuthenticated, IsSuperAdmin]

    def get(self, request):
        return Response({"message": "Welcome SuperAdmin!"})

class LogoutAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        logout(request)  # This clears the session
        return Response({"message": "Logout successful"}, status=status.HTTP_200_OK)