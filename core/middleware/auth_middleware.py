"""
Auth middleware for authentication integration
"""
import logging
from django.conf import settings

logger = logging.getLogger(__name__)


class AuthServiceMiddleware:
    """
    Middleware to handle Auth Service integration
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        # Process request
        response = self.get_response(request)
        
        # Add auth headers to response if needed
        if hasattr(request, 'user_id') and request.user_id:
            response['X-User-ID'] = str(request.user_id)
            
        if hasattr(request, 'tenant_id') and request.tenant_id:
            response['X-Tenant-ID'] = str(request.tenant_id)
            
        return response 