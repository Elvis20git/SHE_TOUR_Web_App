from celery import shared_task
from .models import ObservationActionTracking, SHEObservation
from .services import NotificationService
from django.utils import timezone
from datetime import timedelta
import logging
from django.conf import settings
from django.core.mail import EmailMessage
from django.core.mail import send_mail
import csv
from io import StringIO
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from django.core.mail import EmailMultiAlternatives
from django.contrib.auth import get_user_model
from django.template.loader import render_to_string
from django.db.models import Count

logger = logging.getLogger(__name__)

@shared_task(bind=True, max_retries=3)
def update_overdue_entries(self):
    try:
        updated_count = ObservationActionTracking.update_all_overdue()
        logger.info(f"Updated {updated_count} overdue entries")
        return updated_count
    except Exception as exc:
        logger.error(f"Error updating overdue entries: {exc}")
        raise self.retry(exc=exc, countdown=60)

@shared_task(bind=True, max_retries=3)
def check_deadlines(self):
    try:
        NotificationService.send_deadline_reminders()
        logger.info("Deadline check completed")
    except Exception as exc:
        logger.error(f"Error checking deadlines: {exc}")
        raise self.retry(exc=exc, countdown=60)

@shared_task(bind=True, max_retries=3)
def send_notification_email(self, notification_id):
    try:
        from .models import Notification
        notification = Notification.objects.get(id=notification_id)
        notification.send_email_notification()
        logger.info(f"Sent email notification {notification_id}")
    except Exception as exc:
        logger.error(f"Error sending notification {notification_id}: {exc}")
        raise self.retry(exc=exc, countdown=60)

@shared_task(bind=True, max_retries=3)
def check_approaching_deadlines(self):
    try:
        from .models import Notification, NotificationPreference
        preferences = NotificationPreference.objects.filter(
            notify_before_deadline=True
        ).select_related('user')

        for pref in preferences:
            deadline_date = timezone.now() + timedelta(days=pref.deadline_reminder_days)
            observations = pref.user.sheobservation_set.filter(
                deadline=deadline_date,
                status__in=['open', 'in_progress']
            )

            for obs in observations:
                Notification.objects.create(
                    user=pref.user,
                    notification_type='deadline_approaching',
                    title=f'Deadline Approaching: {obs.title}',
                    message=f'Task due in {pref.deadline_reminder_days} days',
                    related_observation=obs
                )
        logger.info("Completed checking approaching deadlines")
    except Exception as exc:
        logger.error(f"Error checking approaching deadlines: {exc}")
        raise self.retry(exc=exc, countdown=60)


logger = logging.getLogger(__name__)
@shared_task(name='SHE.tasks.send_welcome_email')
def send_welcome_email(username, email, password):
    """
    Send welcome email to newly registered user
    """
    # Verify email settings
    if not settings.EMAIL_HOST_USER:
        logger.error("EMAIL_HOST_USER is not set")
        return False

    subject = 'Welcome to Our Platform - Your Account Details'
    message = f"""
    Hello {username},

    Your account has been created successfully!

    Here are your login credentials:
    Username: {username}
    Password: {password}

    Please login at: {settings.SITE_URL}/login

    For security reasons, we recommend changing your password after your first login.

    Best regards,
    Your Platform Team
    """

    try:
        logger.info(f"Preparing to send email to: {email}")
        logger.info(f"Using sender email: {settings.EMAIL_HOST_USER}")

        email_message = EmailMessage(
            subject=subject,
            body=message,
            from_email=settings.EMAIL_HOST_USER,
            to=[email],
            headers={'From': f'SHE Platform <{settings.EMAIL_HOST_USER}>'}  # Add proper From header
        )

        # Send the email
        sent_count = email_message.send(fail_silently=False)

        if sent_count:
            logger.info(f"Email sent successfully to {email}")
            return True
        else:
            logger.error("No emails were sent")
            return False

    except Exception as e:
        logger.error("An error occurred while sending the email")
        logger.error(str(e))
        return False


@shared_task(name='SHE.tasks.generate_daily_observation_report')
def generate_daily_observation_report():
    try:
        # Get today's date
        today = timezone.now().date()
        print(f"Generating report for {today}")

        # Get all observations from today
        observations = SHEObservation.objects.filter(
            date=today
        ).select_related('reporter')

        print(f"Found {observations.count()} observations for {today}")

        if observations.count() == 0:
            print("No observations found for today - skipping email")
            return "No observations to report"

        # Generate statistics
        stats = {
            'total_observations': observations.count(),
            'by_priority': dict(observations.values_list('priority').annotate(count=Count('priority'))),
            'by_status': dict(observations.values_list('status').annotate(count=Count('status'))),
            'by_issue_type': dict(observations.values_list('issue_type').annotate(count=Count('issue_type'))),
        }
        print(f"Generated stats: {stats}")

        # Generate CSV report
        csv_buffer = StringIO()
        csv_writer = csv.writer(csv_buffer)
        csv_writer.writerow([
            'Date', 'Time', 'Reporter', 'Department', 'Issue Type',
            'Nature of Issue', 'Area', 'Priority', 'Status'
        ])

        for obs in observations:
            csv_writer.writerow([
                obs.date,
                obs.time,
                obs.reporter.get_full_name() if obs.reporter else 'Anonymous',
                obs.department,
                obs.get_issue_type_display(),
                obs.nature_of_issue,
                obs.get_area_display(),
                obs.get_priority_display(),
                obs.get_status_display()
            ])

        # Get all managers
        User = get_user_model()
        User.objects.filter(role__in=['manager', 'administrator']).update(email_notifications=True)
        managers = User.objects.filter(role__in=['manager', 'administrator'])
        print(f"Found {managers.count()} managers")

        # Prepare email
        subject = f'Daily SHE Observation Report - {today}'

        try:
            html_content = render_to_string('notifications/she_observation_report_email.html', {
                'date': today,
                'stats': stats,
                'observations': observations,
            })
            print("HTML template rendered successfully")
        except Exception as e:
            print(f"Error rendering HTML template: {str(e)}")
            raise

        # Send email to each manager
        emails_sent = 0
        for manager in managers:
            print(f"Processing email for {manager.email}")
            if manager.email_notifications:
                try:
                    msg = EmailMultiAlternatives(
                        subject=subject,
                        body='Please see the attached report and summary below.',
                        from_email=settings.EMAIL_HOST_USER,
                        to=[manager.email]
                    )

                    msg.attach_alternative(html_content, "text/html")

                    csv_attachment = MIMEApplication(csv_buffer.getvalue().encode('utf-8'))
                    csv_attachment.add_header(
                        'Content-Disposition',
                        'attachment',
                        filename=f'she_observations_{today}.csv'
                    )
                    msg.attach(csv_attachment)

                    msg.send()
                    emails_sent += 1
                    print(f"Email sent successfully to {manager.email}")
                except Exception as e:
                    print(f"Failed to send email to {manager.email}. Error: {str(e)}")
            else:
                print(f"Skipping {manager.email} - notifications disabled")

        return f"Report generated and sent to {emails_sent} managers"

    except Exception as e:
        print(f"Task failed with error: {str(e)}")
        raise