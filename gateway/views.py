"""
Gateway views for API gateway functionality
"""
import logging
import requests
from django.conf import settings
from django.http import JsonResponse
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.viewsets import ViewSet
from drf_spectacular.utils import extend_schema, OpenApiParameter

logger = logging.getLogger(__name__)


class GatewayViewSet(ViewSet):
    """
    Gateway ViewSet for API routing
    """
    
    @extend_schema(
        summary="Gateway Info",
        description="Get information about the API Gateway",
        responses={200: dict}
    )
    def list(self, request):
        """
        Get gateway information
        """
        return Response({
            'service': 'ERP Core API Gateway',
            'version': '1.0.0',
            'status': 'running',
            'auth_service': settings.AUTH_SERVICE_CONFIG['BASE_URL'],
            'tenant_id': getattr(request, 'tenant_id', 'unknown'),
            'user_id': getattr(request, 'user_id', 'anonymous'),
        })


@extend_schema(
    summary="Health Check",
    description="Check if the API Gateway is healthy",
    responses={200: dict}
)
@api_view(['GET'])
@permission_classes([AllowAny])
def health_check(request):
    """
    Health check endpoint
    """
    try:
        # Check auth service
        auth_client = requests.get(
            f"{settings.AUTH_SERVICE_CONFIG['BASE_URL']}/health",
            timeout=5
        )
        auth_status = 'healthy' if auth_client.status_code == 200 else 'unhealthy'
    except Exception as e:
        logger.error(f"Auth service health check failed: {str(e)}")
        auth_status = 'unreachable'
    
    return JsonResponse({
        'status': 'healthy',
        'service': 'ERP Core API Gateway',
        'version': '1.0.0',
        'dependencies': {
            'auth_service': auth_status,
        }
    })


@extend_schema(
    summary="Service Status",
    description="Get status of all services",
    responses={200: dict}
)
@api_view(['GET'])
def service_status(request):
    """
    Get status of all services
    """
    services = {
        'auth_service': {
            'url': settings.AUTH_SERVICE_CONFIG['BASE_URL'],
            'status': 'checking'
        },
        'database': {
            'url': f"postgresql://{settings.DATABASES['default']['HOST']}:{settings.DATABASES['default']['PORT']}",
            'status': 'checking'
        },
        'redis': {
            'url': f"redis://{settings.REDIS_CONFIG['HOST']}:{settings.REDIS_CONFIG['PORT']}",
            'status': 'checking'
        }
    }
    
    # Check auth service
    try:
        auth_response = requests.get(
            f"{settings.AUTH_SERVICE_CONFIG['BASE_URL']}/health",
            timeout=5
        )
        services['auth_service']['status'] = 'healthy' if auth_response.status_code == 200 else 'unhealthy'
    except Exception as e:
        logger.error(f"Auth service check failed: {str(e)}")
        services['auth_service']['status'] = 'unreachable'
    
    # Check database
    try:
        from django.db import connection
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
        services['database']['status'] = 'healthy'
    except Exception as e:
        logger.error(f"Database check failed: {str(e)}")
        services['database']['status'] = 'unhealthy'
    
    # Check Redis
    try:
        from django.core.cache import cache
        cache.set('health_check', 'ok', 10)
        if cache.get('health_check') == 'ok':
            services['redis']['status'] = 'healthy'
        else:
            services['redis']['status'] = 'unhealthy'
    except Exception as e:
        logger.error(f"Redis check failed: {str(e)}")
        services['redis']['status'] = 'unreachable'
    
    return JsonResponse({
        'gateway': {
            'status': 'healthy',
            'version': '1.0.0'
        },
        'services': services
    })


@extend_schema(
    summary="API Info",
    description="Get API information and documentation links",
    responses={200: dict}
)
@api_view(['GET'])
@permission_classes([AllowAny])
def api_info(request):
    """
    Get API information
    """
    return JsonResponse({
        'name': 'ERP Core API Gateway',
        'version': '1.0.0',
        'description': 'Central API Gateway for ERP Suite with Auth Service Integration',
        'documentation': {
            'swagger': '/api/docs/',
            'redoc': '/api/redoc/',
            'schema': '/api/schema/',
        },
        'endpoints': {
            'health': '/api/v1/health/',
            'status': '/api/v1/status/',
            'auth': '/api/v1/auth/',
            'monitoring': '/api/v1/monitoring/',
        },
        'authentication': {
            'type': 'Bearer Token',
            'header': 'Authorization: Bearer <token>',
        }
    }) 