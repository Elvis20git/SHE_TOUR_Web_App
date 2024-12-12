from django.apps import AppConfig

class SheConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'SHE'

    def ready(self):
        """Import tasks when Django starts"""
        import SHE.tasks