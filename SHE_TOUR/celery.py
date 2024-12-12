# SHE_TOUR/celery.py
import os
from celery import Celery

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'SHE_TOUR.settings')

# Create celery app
app = Celery('SHE_TOUR')

# Load task modules from all registered Django app configs.
app.config_from_object('django.conf:settings', namespace='CELERY')

# Windows specific settings
app.conf.update(
    broker_connection_retry_on_startup=True,
    worker_pool_restarts=True,
    worker_pool='solo',  # Use solo pool for Windows
)

# Auto-discover tasks from all installed apps
app.autodiscover_tasks()