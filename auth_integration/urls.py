"""
URL configuration for Auth Integration app
"""
from django.urls import path
from . import views

urlpatterns = [
    # Auth proxy endpoints
    path('login/', views.login_proxy, name='login_proxy'),
    path('logout/', views.logout_proxy, name='logout_proxy'),
    path('register/', views.register_proxy, name='register_proxy'),
    path('refresh/', views.refresh_token_proxy, name='refresh_token_proxy'),
    path('validate/', views.validate_token_proxy, name='validate_token_proxy'),
    path('forgot-password/', views.forgot_password_proxy, name='forgot_password_proxy'),
    path('reset-password/', views.reset_password_proxy, name='reset_password_proxy'),
    path('me/', views.current_user_proxy, name='current_user_proxy'),
    
    # User management
    path('users/', views.user_list_proxy, name='user_list_proxy'),
    path('users/<str:user_id>/', views.user_detail_proxy, name='user_detail_proxy'),
    path('users/<str:user_id>/permissions/', views.user_permissions_proxy, name='user_permissions_proxy'),
    
    # Permission management
    path('permissions/', views.permission_list_proxy, name='permission_list_proxy'),
    path('check-permission/', views.check_permission_proxy, name='check_permission_proxy'),
] 