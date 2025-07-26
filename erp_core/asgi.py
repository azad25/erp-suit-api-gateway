"""
ASGI config for ERP Core API Gateway
"""

import os

from django.core.asgi import get_asgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'erp_core.settings')

application = get_asgi_application() 