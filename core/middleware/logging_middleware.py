"""
Logging middleware for request logging
"""
import logging
import time
from django.conf import settings

logger = logging.getLogger(__name__)


class RequestLoggingMiddleware:
    """
    Middleware to log all requests
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        # Start time
        start_time = time.time()
        
        # Log request
        self._log_request(request)
        
        # Process request
        response = self.get_response(request)
        
        # Calculate duration
        duration = time.time() - start_time
        
        # Log response
        self._log_response(request, response, duration)
        
        return response
    
    def _log_request(self, request):
        """
        Log incoming request
        """
        user_id = getattr(request, 'user_id', 'anonymous')
        tenant_id = getattr(request, 'tenant_id', 'unknown')
        
        logger.info(
            f"Request: {request.method} {request.path} "
            f"from user {user_id} tenant {tenant_id}"
        )
    
    def _log_response(self, request, response, duration):
        """
        Log response
        """
        user_id = getattr(request, 'user_id', 'anonymous')
        tenant_id = getattr(request, 'tenant_id', 'unknown')
        
        logger.info(
            f"Response: {response.status_code} "
            f"for {request.method} {request.path} "
            f"from user {user_id} tenant {tenant_id} "
            f"took {duration:.3f}s"
        ) 