"""
URL configuration for Gateway app
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'gateway', views.GatewayViewSet, basename='gateway')

urlpatterns = [
    # Gateway routes
    path('', include(router.urls)),
    
    # Health check
    path('health/', views.health_check, name='health_check'),
    
    # Service status
    path('status/', views.service_status, name='service_status'),
    
    # API info
    path('info/', views.api_info, name='api_info'),
] 