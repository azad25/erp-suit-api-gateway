"""
Authentication backend for Auth Service integration
"""
import logging
import requests
from django.conf import settings
from django.contrib.auth.backends import BaseBackend
from django.contrib.auth.models import User
from rest_framework import authentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError

from .services.auth_service import AuthServiceClient

logger = logging.getLogger(__name__)


class AuthServiceAuthentication(authentication.BaseAuthentication):
    """
    Custom authentication class that validates tokens with the Auth Service
    """
    
    def authenticate(self, request):
        """
        Authenticate the request using the Auth Service
        """
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        if not auth_header:
            return None
            
        try:
            # Extract token from header
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
            else:
                token = auth_header
                
            # Validate token with Auth Service
            auth_client = AuthServiceClient()
            user_data = auth_client.validate_token(token)
            
            if not user_data:
                return None
                
            # Create or get user from local database
            user, created = self._get_or_create_user(user_data)
            
            # Add tenant and user info to request
            request.tenant_id = user_data.get('tenant_id')
            request.user_id = user_data.get('user_id')
            request.user_permissions = user_data.get('permissions', [])
            
            return (user, token)
            
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            return None
    
    def _get_or_create_user(self, user_data):
        """
        Get or create a local user based on Auth Service data
        """
        user_id = user_data.get('user_id')
        email = user_data.get('email')
        
        if not user_id or not email:
            return None, False
            
        user, created = User.objects.get_or_create(
            id=user_id,
            defaults={
                'username': email,
                'email': email,
                'first_name': user_data.get('first_name', ''),
                'last_name': user_data.get('last_name', ''),
                'is_active': user_data.get('is_active', True),
            }
        )
        
        if not created:
            # Update user data if it changed
            user.email = email
            user.first_name = user_data.get('first_name', '')
            user.last_name = user_data.get('last_name', '')
            user.is_active = user_data.get('is_active', True)
            user.save()
            
        return user, created


class AuthServiceBackend(BaseBackend):
    """
    Django authentication backend for Auth Service integration
    """
    
    def authenticate(self, request, username=None, password=None):
        """
        Authenticate user with Auth Service
        """
        if not username or not password:
            return None
            
        try:
            auth_client = AuthServiceClient()
            user_data = auth_client.authenticate(username, password)
            
            if not user_data:
                return None
                
            user, created = self._get_or_create_user(user_data)
            return user
            
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            return None
    
    def get_user(self, user_id):
        """
        Get user by ID
        """
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
    
    def _get_or_create_user(self, user_data):
        """
        Get or create a local user based on Auth Service data
        """
        user_id = user_data.get('user_id')
        email = user_data.get('email')
        
        if not user_id or not email:
            return None, False
            
        user, created = User.objects.get_or_create(
            id=user_id,
            defaults={
                'username': email,
                'email': email,
                'first_name': user_data.get('first_name', ''),
                'last_name': user_data.get('last_name', ''),
                'is_active': user_data.get('is_active', True),
            }
        )
        
        if not created:
            # Update user data if it changed
            user.email = email
            user.first_name = user_data.get('first_name', '')
            user.last_name = user_data.get('last_name', '')
            user.is_active = user_data.get('is_active', True)
            user.save()
            
        return user, created 