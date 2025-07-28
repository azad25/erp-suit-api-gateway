"""
Auth Integration views for proxying auth service requests
"""
import logging
import requests
from django.conf import settings
from django.http import JsonResponse
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from drf_spectacular.utils import extend_schema

from core.services.auth_service import AuthServiceClient

logger = logging.getLogger(__name__)


@extend_schema(
    summary="Login Proxy",
    description="Proxy login request to Auth Service",
    responses={200: dict, 401: dict}
)
@api_view(['POST'])
@permission_classes([AllowAny])
def login_proxy(request):
    """
    Proxy login request to Auth Service
    """
    try:
        auth_client = AuthServiceClient()
        
        # Forward request to auth service
        response = requests.post(
            f"{settings.AUTH_SERVICE_CONFIG['BASE_URL']}/api/v1/auth/login",
            json=request.data,
            timeout=settings.AUTH_SERVICE_CONFIG['TIMEOUT']
        )
        
        if response.status_code == 200:
            return Response(response.json(), status=status.HTTP_200_OK)
        else:
            return Response(
                response.json() if response.content else {'error': 'Authentication failed'},
                status=response.status_code
            )
            
    except Exception as e:
        logger.error(f"Login proxy error: {str(e)}")
        return Response(
            {'error': 'Internal server error'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@extend_schema(
    summary="Logout Proxy",
    description="Proxy logout request to Auth Service",
    responses={200: dict}
)
@api_view(['POST'])
def logout_proxy(request):
    """
    Proxy logout request to Auth Service
    """
    try:
        # Forward request to auth service
        response = requests.post(
            f"{settings.AUTH_SERVICE_CONFIG['BASE_URL']}/api/v1/auth/logout",
            headers={'Authorization': request.META.get('HTTP_AUTHORIZATION', '')},
            timeout=settings.AUTH_SERVICE_CONFIG['TIMEOUT']
        )
        
        if response.status_code == 200:
            return Response(response.json(), status=status.HTTP_200_OK)
        else:
            return Response(
                response.json() if response.content else {'error': 'Logout failed'},
                status=response.status_code
            )
            
    except Exception as e:
        logger.error(f"Logout proxy error: {str(e)}")
        return Response(
            {'error': 'Internal server error'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@extend_schema(
    summary="Register Proxy",
    description="Proxy registration request to Auth Service",
    responses={201: dict, 400: dict}
)
@api_view(['POST'])
@permission_classes([AllowAny])
def register_proxy(request):
    """
    Proxy registration request to Auth Service
    """
    try:
        # Forward request to auth service
        response = requests.post(
            f"{settings.AUTH_SERVICE_CONFIG['BASE_URL']}/api/v1/auth/register",
            json=request.data,
            timeout=settings.AUTH_SERVICE_CONFIG['TIMEOUT']
        )
        
        if response.status_code == 201:
            return Response(response.json(), status=status.HTTP_201_CREATED)
        else:
            return Response(
                response.json() if response.content else {'error': 'Registration failed'},
                status=response.status_code
            )
            
    except Exception as e:
        logger.error(f"Register proxy error: {str(e)}")
        return Response(
            {'error': 'Internal server error'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@extend_schema(
    summary="Refresh Token Proxy",
    description="Proxy token refresh request to Auth Service",
    responses={200: dict, 401: dict}
)
@api_view(['POST'])
@permission_classes([AllowAny])
def refresh_token_proxy(request):
    """
    Proxy token refresh request to Auth Service
    """
    try:
        auth_client = AuthServiceClient()
        result = auth_client.refresh_token(request.data.get('refresh_token'))
        
        if result:
            return Response(result, status=status.HTTP_200_OK)
        else:
            return Response(
                {'error': 'Token refresh failed'},
                status=status.HTTP_401_UNAUTHORIZED
            )
            
    except Exception as e:
        logger.error(f"Token refresh proxy error: {str(e)}")
        return Response(
            {'error': 'Internal server error'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@extend_schema(
    summary="Validate Token Proxy",
    description="Proxy token validation request to Auth Service",
    responses={200: dict, 401: dict}
)
@api_view(['GET'])
def validate_token_proxy(request):
    """
    Proxy token validation request to Auth Service
    """
    try:
        auth_client = AuthServiceClient()
        token = request.META.get('HTTP_AUTHORIZATION', '').replace('Bearer ', '')
        
        if not token:
            return Response(
                {'error': 'No token provided'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        user_data = auth_client.validate_token(token)
        
        if user_data:
            return Response(user_data, status=status.HTTP_200_OK)
        else:
            return Response(
                {'error': 'Invalid token'},
                status=status.HTTP_401_UNAUTHORIZED
            )
            
    except Exception as e:
        logger.error(f"Token validation proxy error: {str(e)}")
        return Response(
            {'error': 'Internal server error'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@extend_schema(
    summary="User List Proxy",
    description="Proxy user list request to Auth Service",
    responses={200: dict}
)
@api_view(['GET'])
def user_list_proxy(request):
    """
    Proxy user list request to Auth Service
    """
    try:
        # Forward request to auth service
        response = requests.get(
            f"{settings.AUTH_SERVICE_CONFIG['BASE_URL']}/api/v1/users/",
            headers={'Authorization': request.META.get('HTTP_AUTHORIZATION', '')},
            params=request.GET,
            timeout=settings.AUTH_SERVICE_CONFIG['TIMEOUT']
        )
        
        if response.status_code == 200:
            return Response(response.json(), status=status.HTTP_200_OK)
        else:
            return Response(
                response.json() if response.content else {'error': 'Failed to get users'},
                status=response.status_code
            )
            
    except Exception as e:
        logger.error(f"User list proxy error: {str(e)}")
        return Response(
            {'error': 'Internal server error'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@extend_schema(
    summary="User Detail Proxy",
    description="Proxy user detail request to Auth Service",
    responses={200: dict, 404: dict}
)
@api_view(['GET'])
def user_detail_proxy(request, user_id):
    """
    Proxy user detail request to Auth Service
    """
    try:
        auth_client = AuthServiceClient()
        user_data = auth_client.get_user_info(user_id)
        
        if user_data:
            return Response(user_data, status=status.HTTP_200_OK)
        else:
            return Response(
                {'error': 'User not found'},
                status=status.HTTP_404_NOT_FOUND
            )
            
    except Exception as e:
        logger.error(f"User detail proxy error: {str(e)}")
        return Response(
            {'error': 'Internal server error'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@extend_schema(
    summary="User Permissions Proxy",
    description="Proxy user permissions request to Auth Service",
    responses={200: dict}
)
@api_view(['GET'])
def user_permissions_proxy(request, user_id):
    """
    Proxy user permissions request to Auth Service
    """
    try:
        auth_client = AuthServiceClient()
        permissions = auth_client.get_user_permissions(user_id)
        
        return Response({'permissions': permissions}, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(f"User permissions proxy error: {str(e)}")
        return Response(
            {'error': 'Internal server error'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@extend_schema(
    summary="Permission List Proxy",
    description="Proxy permission list request to Auth Service",
    responses={200: dict}
)
@api_view(['GET'])
def permission_list_proxy(request):
    """
    Proxy permission list request to Auth Service
    """
    try:
        # Forward request to auth service
        response = requests.get(
            f"{settings.AUTH_SERVICE_CONFIG['BASE_URL']}/api/v1/permissions/",
            headers={'Authorization': request.META.get('HTTP_AUTHORIZATION', '')},
            timeout=settings.AUTH_SERVICE_CONFIG['TIMEOUT']
        )
        
        if response.status_code == 200:
            return Response(response.json(), status=status.HTTP_200_OK)
        else:
            return Response(
                response.json() if response.content else {'error': 'Failed to get permissions'},
                status=response.status_code
            )
            
    except Exception as e:
        logger.error(f"Permission list proxy error: {str(e)}")
        return Response(
            {'error': 'Internal server error'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@extend_schema(
    summary="Check Permission Proxy",
    description="Proxy permission check request to Auth Service",
    responses={200: dict}
)
@api_view(['POST'])
def check_permission_proxy(request):
    """
    Proxy permission check request to Auth Service
    """
    try:
        auth_client = AuthServiceClient()
        user_id = request.data.get('user_id')
        permission = request.data.get('permission')
        
        if not user_id or not permission:
            return Response(
                {'error': 'user_id and permission are required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        has_permission = auth_client.check_permission(user_id, permission)
        
        return Response({
            'user_id': user_id,
            'permission': permission,
            'has_permission': has_permission
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(f"Permission check proxy error: {str(e)}")
        return Response(
            {'error': 'Internal server error'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@extend_schema(
    summary="Forgot Password Proxy",
    description="Proxy forgot password request to Auth Service",
    responses={200: dict, 400: dict}
)
@api_view(['POST'])
@permission_classes([AllowAny])
def forgot_password_proxy(request):
    """
    Proxy forgot password request to Auth Service
    """
    try:
        # Forward request to auth service
        response = requests.post(
            f"{settings.AUTH_SERVICE_CONFIG['BASE_URL']}/api/v1/auth/forgot-password",
            json=request.data,
            timeout=settings.AUTH_SERVICE_CONFIG['TIMEOUT']
        )
        
        if response.status_code == 200:
            return Response(response.json(), status=status.HTTP_200_OK)
        else:
            return Response(
                response.json() if response.content else {'error': 'Failed to send reset instructions'},
                status=response.status_code
            )
            
    except Exception as e:
        logger.error(f"Forgot password proxy error: {str(e)}")
        return Response(
            {'error': 'Internal server error'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@extend_schema(
    summary="Reset Password Proxy",
    description="Proxy reset password request to Auth Service",
    responses={200: dict, 400: dict}
)
@api_view(['POST'])
@permission_classes([AllowAny])
def reset_password_proxy(request):
    """
    Proxy reset password request to Auth Service
    """
    try:
        # Forward request to auth service
        response = requests.post(
            f"{settings.AUTH_SERVICE_CONFIG['BASE_URL']}/api/v1/auth/reset-password",
            json=request.data,
            timeout=settings.AUTH_SERVICE_CONFIG['TIMEOUT']
        )
        
        if response.status_code == 200:
            return Response(response.json(), status=status.HTTP_200_OK)
        else:
            return Response(
                response.json() if response.content else {'error': 'Failed to reset password'},
                status=response.status_code
            )
            
    except Exception as e:
        logger.error(f"Reset password proxy error: {str(e)}")
        return Response(
            {'error': 'Internal server error'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@extend_schema(
    summary="Current User Proxy",
    description="Proxy current user request to Auth Service",
    responses={200: dict, 401: dict}
)
@api_view(['GET'])
def current_user_proxy(request):
    """
    Proxy current user request to Auth Service
    """
    try:
        # Forward request to auth service
        response = requests.get(
            f"{settings.AUTH_SERVICE_CONFIG['BASE_URL']}/api/v1/users/profile",
            headers={'Authorization': request.META.get('HTTP_AUTHORIZATION', '')},
            timeout=settings.AUTH_SERVICE_CONFIG['TIMEOUT']
        )
        
        if response.status_code == 200:
            return Response(response.json(), status=status.HTTP_200_OK)
        else:
            return Response(
                response.json() if response.content else {'error': 'Failed to get user profile'},
                status=response.status_code
            )
            
    except Exception as e:
        logger.error(f"Current user proxy error: {str(e)}")
        return Response(
            {'error': 'Internal server error'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )