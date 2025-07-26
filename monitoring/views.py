"""
Monitoring views for metrics and health checks
"""
import logging
import psutil
import requests
from django.conf import settings
from django.http import JsonResponse
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from drf_spectacular.utils import extend_schema

logger = logging.getLogger(__name__)


@extend_schema(
    summary="Metrics",
    description="Get system metrics",
    responses={200: dict}
)
@api_view(['GET'])
def metrics(request):
    """
    Get system metrics
    """
    try:
        # System metrics
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # Process metrics
        process = psutil.Process()
        process_memory = process.memory_info()
        
        metrics_data = {
            'system': {
                'cpu_percent': cpu_percent,
                'memory': {
                    'total': memory.total,
                    'available': memory.available,
                    'percent': memory.percent,
                    'used': memory.used,
                },
                'disk': {
                    'total': disk.total,
                    'used': disk.used,
                    'free': disk.free,
                    'percent': (disk.used / disk.total) * 100,
                }
            },
            'process': {
                'memory_rss': process_memory.rss,
                'memory_vms': process_memory.vms,
                'cpu_percent': process.cpu_percent(),
                'num_threads': process.num_threads(),
            },
            'timestamp': psutil.boot_time()
        }
        
        return JsonResponse(metrics_data)
        
    except Exception as e:
        logger.error(f"Metrics error: {str(e)}")
        return JsonResponse(
            {'error': 'Failed to get metrics'},
            status=500
        )


@extend_schema(
    summary="Performance Metrics",
    description="Get performance metrics",
    responses={200: dict}
)
@api_view(['GET'])
def performance_metrics(request):
    """
    Get performance metrics
    """
    try:
        # Database performance
        from django.db import connection
        with connection.cursor() as cursor:
            cursor.execute("SELECT version()")
            db_version = cursor.fetchone()[0]
        
        # Cache performance
        from django.core.cache import cache
        cache_start = psutil.Process().cpu_times()
        cache.set('performance_test', 'test_value', 10)
        cache.get('performance_test')
        cache_end = psutil.Process().cpu_times()
        cache_time = (cache_end.user + cache_end.system) - (cache_start.user + cache_start.system)
        
        performance_data = {
            'database': {
                'version': db_version,
                'connections': len(connection.queries) if hasattr(connection, 'queries') else 0,
            },
            'cache': {
                'response_time_ms': cache_time * 1000,
                'status': 'healthy' if cache.get('performance_test') == 'test_value' else 'unhealthy'
            },
            'auth_service': {
                'response_time_ms': 0,
                'status': 'unknown'
            }
        }
        
        # Check auth service performance
        try:
            import time
            start_time = time.time()
            response = requests.get(
                f"{settings.AUTH_SERVICE_CONFIG['BASE_URL']}/health",
                timeout=5
            )
            end_time = time.time()
            
            performance_data['auth_service'] = {
                'response_time_ms': (end_time - start_time) * 1000,
                'status': 'healthy' if response.status_code == 200 else 'unhealthy'
            }
        except Exception as e:
            performance_data['auth_service'] = {
                'response_time_ms': 0,
                'status': 'unreachable',
                'error': str(e)
            }
        
        return JsonResponse(performance_data)
        
    except Exception as e:
        logger.error(f"Performance metrics error: {str(e)}")
        return JsonResponse(
            {'error': 'Failed to get performance metrics'},
            status=500
        )


@extend_schema(
    summary="Error Metrics",
    description="Get error metrics",
    responses={200: dict}
)
@api_view(['GET'])
def error_metrics(request):
    """
    Get error metrics
    """
    try:
        # This would typically come from a logging system or monitoring service
        # For now, we'll return basic error metrics
        error_data = {
            'errors': {
                'total_errors': 0,
                'errors_last_hour': 0,
                'errors_last_24h': 0,
                'error_rate': 0.0,
            },
            'exceptions': {
                'total_exceptions': 0,
                'exceptions_last_hour': 0,
                'exceptions_last_24h': 0,
            },
            'status_codes': {
                '4xx_errors': 0,
                '5xx_errors': 0,
            }
        }
        
        return JsonResponse(error_data)
        
    except Exception as e:
        logger.error(f"Error metrics error: {str(e)}")
        return JsonResponse(
            {'error': 'Failed to get error metrics'},
            status=500
        )


@extend_schema(
    summary="Detailed Health Check",
    description="Get detailed health check information",
    responses={200: dict}
)
@api_view(['GET'])
@permission_classes([AllowAny])
def detailed_health_check(request):
    """
    Get detailed health check information
    """
    try:
        health_data = {
            'status': 'healthy',
            'checks': {
                'database': {
                    'status': 'checking',
                    'details': {}
                },
                'cache': {
                    'status': 'checking',
                    'details': {}
                },
                'auth_service': {
                    'status': 'checking',
                    'details': {}
                }
            }
        }
        
        # Check database
        try:
            from django.db import connection
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                health_data['checks']['database'] = {
                    'status': 'healthy',
                    'details': {
                        'connection': 'ok',
                        'query_time_ms': 0
                    }
                }
        except Exception as e:
            health_data['checks']['database'] = {
                'status': 'unhealthy',
                'details': {
                    'error': str(e)
                }
            }
            health_data['status'] = 'unhealthy'
        
        # Check cache
        try:
            from django.core.cache import cache
            cache.set('health_check', 'ok', 10)
            if cache.get('health_check') == 'ok':
                health_data['checks']['cache'] = {
                    'status': 'healthy',
                    'details': {
                        'connection': 'ok',
                        'read_write': 'ok'
                    }
                }
            else:
                health_data['checks']['cache'] = {
                    'status': 'unhealthy',
                    'details': {
                        'error': 'Cache read/write failed'
                    }
                }
                health_data['status'] = 'unhealthy'
        except Exception as e:
            health_data['checks']['cache'] = {
                'status': 'unhealthy',
                'details': {
                    'error': str(e)
                }
            }
            health_data['status'] = 'unhealthy'
        
        # Check auth service
        try:
            response = requests.get(
                f"{settings.AUTH_SERVICE_CONFIG['BASE_URL']}/health",
                timeout=5
            )
            if response.status_code == 200:
                health_data['checks']['auth_service'] = {
                    'status': 'healthy',
                    'details': {
                        'response_time_ms': response.elapsed.total_seconds() * 1000,
                        'status_code': response.status_code
                    }
                }
            else:
                health_data['checks']['auth_service'] = {
                    'status': 'unhealthy',
                    'details': {
                        'status_code': response.status_code,
                        'error': 'Auth service returned non-200 status'
                    }
                }
                health_data['status'] = 'unhealthy'
        except Exception as e:
            health_data['checks']['auth_service'] = {
                'status': 'unreachable',
                'details': {
                    'error': str(e)
                }
            }
            health_data['status'] = 'unhealthy'
        
        return JsonResponse(health_data)
        
    except Exception as e:
        logger.error(f"Detailed health check error: {str(e)}")
        return JsonResponse(
            {
                'status': 'unhealthy',
                'error': 'Failed to perform health check',
                'details': str(e)
            },
            status=500
        )


@extend_schema(
    summary="Services Health Check",
    description="Get health check for all services",
    responses={200: dict}
)
@api_view(['GET'])
@permission_classes([AllowAny])
def services_health_check(request):
    """
    Get health check for all services
    """
    try:
        services = {
            'postgresql': {
                'url': f"postgresql://{settings.DATABASES['default']['HOST']}:{settings.DATABASES['default']['PORT']}",
                'status': 'checking'
            },
            'redis': {
                'url': f"redis://{settings.REDIS_CONFIG['HOST']}:{settings.REDIS_CONFIG['PORT']}",
                'status': 'checking'
            },
            'auth_service': {
                'url': settings.AUTH_SERVICE_CONFIG['BASE_URL'],
                'status': 'checking'
            }
        }
        
        # Check PostgreSQL
        try:
            from django.db import connection
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
            services['postgresql']['status'] = 'healthy'
        except Exception as e:
            services['postgresql']['status'] = 'unhealthy'
            services['postgresql']['error'] = str(e)
        
        # Check Redis
        try:
            from django.core.cache import cache
            cache.set('health_check', 'ok', 10)
            if cache.get('health_check') == 'ok':
                services['redis']['status'] = 'healthy'
            else:
                services['redis']['status'] = 'unhealthy'
        except Exception as e:
            services['redis']['status'] = 'unreachable'
            services['redis']['error'] = str(e)
        
        # Check Auth Service
        try:
            response = requests.get(
                f"{settings.AUTH_SERVICE_CONFIG['BASE_URL']}/health",
                timeout=5
            )
            if response.status_code == 200:
                services['auth_service']['status'] = 'healthy'
            else:
                services['auth_service']['status'] = 'unhealthy'
                services['auth_service']['error'] = f"Status code: {response.status_code}"
        except Exception as e:
            services['auth_service']['status'] = 'unreachable'
            services['auth_service']['error'] = str(e)
        
        return JsonResponse({
            'gateway': {
                'status': 'healthy',
                'version': '1.0.0'
            },
            'services': services
        })
        
    except Exception as e:
        logger.error(f"Services health check error: {str(e)}")
        return JsonResponse(
            {'error': 'Failed to check services health'},
            status=500
        ) 