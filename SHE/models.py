# In your users/models.py file
from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _


class CustomUser(AbstractUser):
    email = models.EmailField(_("Email Address"), unique=True)
    department = models.CharField(_("Department"), max_length=100, blank=True)
    position = models.CharField(_("Position"), max_length=100, blank=True)

    # New field to store the role
    ROLE_CHOICES = [
        ('user', 'User'),
        ('manager', 'Manager'),
        ('administrator', 'Administrator'),
    ]
    role = models.CharField(_("Role"), max_length=20, choices=ROLE_CHOICES, default='user')

    def __str__(self):
        return self.username

    def get_full_name(self):
        full_name = super().get_full_name()
        if full_name:
            return full_name
        return self.username



User = settings.AUTH_USER_MODEL

class SHEObservation(models.Model):
    ISSUE_TYPES = [
        ('unsafe_condition', 'Unsafe Condition'),
        ('near_miss', 'Near Miss'),
        ('bbs', 'Behavioral Based Safety (BBS)'),
    ]
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('closed', 'Closed'),
    ]
    PRIORITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
    ]

    reporter = models.ForeignKey(User, on_delete=models.CASCADE, related_name='reported_observations', blank=True, null=True)
    department = models.CharField(max_length=100)
    date = models.DateField()
    time = models.TimeField()
    area = models.CharField(max_length=100)
    nature_of_issue = models.TextField()
    issue_type = models.CharField(max_length=20, choices=ISSUE_TYPES)
    corrective_action = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    priority = models.CharField(max_length=10, choices=PRIORITY_CHOICES, default='medium')
    # assigned_to = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='assigned_observations')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        if self.reporter:
            return f"Observed by {self.reporter.get_full_name()} on {self.date}"
        return f"Observation on {self.date}"

class AuditTrail(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    action = models.CharField(max_length=255)
    timestamp = models.DateTimeField(auto_now_add=True)
    observation = models.ForeignKey(SHEObservation, on_delete=models.CASCADE)

    def __str__(self):
        return f"{self.user.username} - {self.action} - {self.timestamp}"

class Feedback(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Feedback by {self.user.username} on {self.created_at}"





class ObservationActionTrackingManager(models.Manager):
    def update_overdue(self):
        return self.filter(
            deadline__lte=timezone.now().date(),
            status__in=['pending', 'in_progress']
        ).update(status='overdue')

class ObservationActionTracking(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('closed', 'Closed'),
        ('overdue', 'Overdue'),
    ]

    date = models.DateField(default=timezone.now)
    she_observation = models.ForeignKey('SHEObservation', on_delete=models.CASCADE, related_name='tracking_entries')
    action = models.TextField()
    assign_to = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='assigned_tracking_entries'
    )
    deadline = models.DateField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')

    objects = ObservationActionTrackingManager()

    def __str__(self):
        return f"Tracking for {self.she_observation} on {self.date}"

    @property
    def observation(self):
        return self.she_observation.nature_of_issue

    def save(self, *args, **kwargs):
        if not self.action:
            self.action = self.she_observation.corrective_action
        self.update_status()
        super().save(*args, **kwargs)

    def update_status(self):
        if self.deadline and self.deadline <= timezone.now().date() and self.status in ['pending', 'in_progress']:
            self.status = 'overdue'

    @classmethod
    def update_all_overdue(cls):
        return cls.objects.update_overdue()

    class Meta:
        ordering = ['-date']
        verbose_name = "Observation Action Tracking"
        verbose_name_plural = "Observation Action Trackings"