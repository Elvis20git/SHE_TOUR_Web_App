from django.core.management.base import BaseCommand
from SHE.models import ObservationActionTracking

class Command(BaseCommand):
    help = 'Updates the status of overdue ObservationActionTracking entries'

    def handle(self, *args, **options):
        updated_count = ObservationActionTracking.update_all_overdue()
        self.stdout.write(self.style.SUCCESS(f'Successfully updated {updated_count} overdue entries'))