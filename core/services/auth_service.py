"""
Auth Service client for communicating with the auth-module
"""
import logging
import requests
import grpc
from django.conf import settings
from django.core.cache import cache
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


class AuthServiceClient:
    """
    Client for communicating with the Auth Service
    """
    
    def __init__(self):
        self.base_url = settings.AUTH_SERVICE_CONFIG['BASE_URL']
        self.timeout = settings.AUTH_SERVICE_CONFIG['TIMEOUT']
        self.retry_attempts = settings.AUTH_SERVICE_CONFIG['RETRY_ATTEMPTS']
        
    def validate_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Validate JWT token with Auth Service
        """
        cache_key = f"auth_token_{token[:20]}"
        
        # Check cache first
        cached_data = cache.get(cache_key)
        if cached_data:
            return cached_data
            
        try:
            url = f"{self.base_url}/api/auth/validate"
            headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            }
            
            response = requests.get(
                url,
                headers=headers,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                user_data = response.json()
                # Cache for 5 minutes
                cache.set(cache_key, user_data, 300)
                return user_data
            else:
                logger.warning(f"Token validation failed: {response.status_code}")
                return None
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Auth service request failed: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Token validation error: {str(e)}")
            return None
    
    def authenticate(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """
        Authenticate user with Auth Service
        """
        try:
            url = f"{self.base_url}/api/auth/login"
            data = {
                'username': username,
                'password': password
            }
            
            response = requests.post(
                url,
                json=data,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.warning(f"Authentication failed: {response.status_code}")
                return None
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Auth service request failed: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            return None
    
    def get_user_info(self, user_id: str) -> Optional[Dict[str, Any]]:
        """
        Get user information from Auth Service
        """
        cache_key = f"user_info_{user_id}"
        
        # Check cache first
        cached_data = cache.get(cache_key)
        if cached_data:
            return cached_data
            
        try:
            url = f"{self.base_url}/api/users/{user_id}"
            
            response = requests.get(
                url,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                user_data = response.json()
                # Cache for 10 minutes
                cache.set(cache_key, user_data, 600)
                return user_data
            else:
                logger.warning(f"Get user info failed: {response.status_code}")
                return None
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Auth service request failed: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Get user info error: {str(e)}")
            return None
    
    def check_permission(self, user_id: str, permission: str) -> bool:
        """
        Check if user has specific permission
        """
        try:
            url = f"{self.base_url}/api/auth/check-permission"
            data = {
                'user_id': user_id,
                'permission': permission
            }
            
            response = requests.post(
                url,
                json=data,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                result = response.json()
                return result.get('has_permission', False)
            else:
                logger.warning(f"Permission check failed: {response.status_code}")
                return False
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Auth service request failed: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Permission check error: {str(e)}")
            return False
    
    def get_user_permissions(self, user_id: str) -> list:
        """
        Get all permissions for a user
        """
        cache_key = f"user_permissions_{user_id}"
        
        # Check cache first
        cached_data = cache.get(cache_key)
        if cached_data:
            return cached_data
            
        try:
            url = f"{self.base_url}/api/users/{user_id}/permissions"
            
            response = requests.get(
                url,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                permissions = response.json().get('permissions', [])
                # Cache for 5 minutes
                cache.set(cache_key, permissions, 300)
                return permissions
            else:
                logger.warning(f"Get user permissions failed: {response.status_code}")
                return []
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Auth service request failed: {str(e)}")
            return []
        except Exception as e:
            logger.error(f"Get user permissions error: {str(e)}")
            return []
    
    def refresh_token(self, refresh_token: str) -> Optional[Dict[str, Any]]:
        """
        Refresh access token
        """
        try:
            url = f"{self.base_url}/api/auth/refresh"
            data = {
                'refresh_token': refresh_token
            }
            
            response = requests.post(
                url,
                json=data,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.warning(f"Token refresh failed: {response.status_code}")
                return None
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Auth service request failed: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Token refresh error: {str(e)}")
            return None 