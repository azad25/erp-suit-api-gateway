"""
URL configuration for Monitoring app
"""
from django.urls import path
from . import views

urlpatterns = [
    # Metrics endpoints
    path('metrics/', views.metrics, name='metrics'),
    path('performance/', views.performance_metrics, name='performance_metrics'),
    path('errors/', views.error_metrics, name='error_metrics'),
    
    # Health checks
    path('health/detailed/', views.detailed_health_check, name='detailed_health_check'),
    path('health/services/', views.services_health_check, name='services_health_check'),
] 