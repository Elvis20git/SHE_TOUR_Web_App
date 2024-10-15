import os
from celery import Celery

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'your_project.settings')

app = Celery('SHE_TOUR')

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes.
app.config_from_object('django.conf:settings', namespace='CELERY')

# Load task modules from all registered Django apps.
app.autodiscover_tasks()

# Set up periodic task
from celery.schedules import crontab

app.conf.beat_schedule = {
    'update-overdue-entries-daily': {
        'task': 'your_app.tasks.update_overdue_entries',
        'schedule': crontab(minute=0, hour=0),  # Run daily at midnight
    },
}