from celery import shared_task
from .models import ObservationActionTracking

@shared_task
def update_overdue_entries():
    updated_count = ObservationActionTracking.update_all_overdue()
    print(f"Updated {updated_count} overdue entries")
    return updated_count