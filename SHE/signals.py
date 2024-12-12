from django.db.models.signals import post_save
from django.dispatch import receiver
from SHE.models import ObservationActionTracking, Notification
from SHE.services import NotificationService
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from .tasks import send_notification_email
@receiver(post_save, sender=ObservationActionTracking)
def notify_on_action_tracking_change(sender, instance, created, **kwargs):
    """Send notifications when action tracking changes"""
    if created:
        if instance.assign_to.notificationpreference.notify_on_assignment:
            NotificationService.create_notification(
                user=instance.assign_to,
                notification_type='assignment',
                title='New Action Assigned',
                message=f'You have been assigned a new action: {instance.action}',
                observation=instance.she_observation
            )

    elif instance.tracker.has_changed('status'):
        NotificationService.create_notification(
            user=instance.she_observation.reporter,
            notification_type='status_change',
            title='Action Status Updated',
            message=f'Action status changed to {instance.get_status_display()}',
            observation=instance.she_observation
        )


@receiver(post_save, sender=Notification)
def notification_created(sender, instance, created, **kwargs):
    if created:
        # Send WebSocket notification
        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(
            f"user_{instance.user.id}",
            {
                "type": "notification_message",
                "message": {
                    "type": instance.notification_type,
                    "title": instance.title,
                    "message": instance.message
                }
            }
        )

        # Queue email task
        if instance.user.notificationpreference.email_notifications:
            send_notification_email.delay(instance.id)