"""
WSGI config for ERP Core API Gateway
"""

import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'erp_core.settings')

application = get_wsgi_application() 