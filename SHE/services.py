from django.utils import timezone

from SHE.models import Notification, ObservationActionTracking


class NotificationService:
    @staticmethod
    def create_notification(user, notification_type, title, message, observation=None):
        """Create and send notification"""
        notification = Notification.objects.create(
            user=user,
            notification_type=notification_type,
            title=title,
            message=message,
            related_observation=observation
        )

        # Send email if enabled
        notification.send_email_notification()

        return notification

    @staticmethod
    def send_deadline_reminders():
        """Send reminders for approaching deadlines"""
        today = timezone.now().date()

        for tracking in ObservationActionTracking.objects.filter(status__in=['pending', 'in_progress']):
            if tracking.deadline:
                days_until_deadline = (tracking.deadline - today).days
                user_preference = tracking.assign_to.notificationpreference

                if (days_until_deadline == user_preference.deadline_reminder_days and
                        user_preference.notify_before_deadline):
                    NotificationService.create_notification(
                        user=tracking.assign_to,
                        notification_type='deadline_approaching',
                        title=f'Deadline Approaching: {tracking.action}',
                        message=f'Task due in {days_until_deadline} days',
                        observation=tracking.she_observation
                    )