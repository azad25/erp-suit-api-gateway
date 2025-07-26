"""
Tenant middleware for multi-tenant support
"""
import logging
from django.conf import settings

logger = logging.getLogger(__name__)


class TenantMiddleware:
    """
    Middleware to handle tenant isolation
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        # Extract tenant from request
        tenant_id = self._extract_tenant_id(request)
        
        # Set tenant in request
        request.tenant_id = tenant_id
        
        # Add tenant to request for logging
        if hasattr(request, 'user_id'):
            logger.info(f"Request from tenant {tenant_id}, user {request.user_id}")
        
        response = self.get_response(request)
        return response
    
    def _extract_tenant_id(self, request):
        """
        Extract tenant ID from request
        """
        # Try to get from header first
        tenant_id = request.META.get('HTTP_X_TENANT_ID')
        
        if not tenant_id:
            # Try to get from user data if authenticated
            if hasattr(request, 'tenant_id'):
                tenant_id = request.tenant_id
        
        if not tenant_id:
            # Default tenant for development
            tenant_id = 'default'
            
        return tenant_id 