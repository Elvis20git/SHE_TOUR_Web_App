import os

from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.models import Permission
from django.contrib.postgres.search import SearchVectorField
from django.contrib.postgres.indexes import GinIndex
from django.core.validators import MinValueValidator, MaxValueValidator, FileExtensionValidator
from django.core.mail import send_mail
from django.template.loader import render_to_string
import json

from django.contrib.auth.models import AbstractUser, Permission
from django.db import models
from django.utils.translation import gettext_lazy as _
from django.core.validators import MinValueValidator, MaxValueValidator


class CustomUser(AbstractUser):
    email = models.EmailField(_("Email Address"), unique=True)
    department = models.CharField(_("Department"), max_length=100, blank=True)
    position = models.CharField(_("Position"), max_length=100, blank=True)
    email_notifications = models.BooleanField(default=True)
    reminder_frequency = models.IntegerField(
        default=1,
        validators=[MinValueValidator(1), MaxValueValidator(30)],
        help_text="Reminder frequency in days",
        null=True,
        blank=True
    )

    ROLE_CHOICES = [
        ('user', 'User'),
        ('manager', 'Manager'),
        ('administrator', 'Administrator'),
    ]
    is_HOD = models.BooleanField(default=False)

    # Define permissions for each role
    ROLE_PERMISSIONS = {
        'user': [
            'view_task',
            'add_task',
            'change_task',
            'delete_task',
        ],
        'manager': [
            'view_task',
            'add_task',
            'change_task',
            'delete_task',
            'view_report',
            'add_report',
            'change_report',
            'delete_report',
        ],
        'administrator': [
            'view_task',
            'add_task',
            'change_task',
            'delete_task',
            'view_report',
            'add_report',
            'change_report',
            'delete_report',
            'view_user',
            'add_user',
            'change_user',
            'delete_user',
        ]
    }

    role = models.CharField(_("Role"), max_length=20, choices=ROLE_CHOICES, default='user')

    @property
    def is_administrator(self):
        """Check if user has administrator role"""
        return self.role == 'administrator'

    @property
    def is_manager_or_above(self):
        """Check if user has manager or administrator role"""
        return self.role in ['manager', 'administrator']
    def save(self, *args, **kwargs):
        """Override save to handle permission assignment"""
        is_new = self.pk is None

        if is_new:
            super().save(*args, **kwargs)
            self._assign_role_permissions()
        else:
            # Get the current role from the database
            if self.pk:
                old_role = CustomUser.objects.get(pk=self.pk).role
                super().save(*args, **kwargs)
                if old_role != self.role:
                    self._assign_role_permissions()
            else:
                super().save(*args, **kwargs)

    def _assign_role_permissions(self):
        """Assign permissions based on user role"""
        # Clear existing permissions
        self.user_permissions.clear()

        # Get permissions for the role
        role_permissions = self.ROLE_PERMISSIONS.get(self.role, [])

        # Assign new permissions
        for permission_codename in role_permissions:
            try:
                permission = Permission.objects.get(codename=permission_codename)
                self.user_permissions.add(permission)
            except Permission.DoesNotExist:
                continue

    class Meta:
        verbose_name = _('user')
        verbose_name_plural = _('users')


User = settings.AUTH_USER_MODEL


class SHEObservation(models.Model):
    ISSUE_TYPES = (
        ('unsafe_condition', 'Unsafe Condition'),
        ('unsafe_acts', 'Unsafe Acts'),
        ('environmental_hazard', 'Environmental Hazard'),
        ('health_concern', 'Health Concern'),
        ('near_miss', 'Near Miss'),
        ('bbs', 'Behavioral Based Safety (BBS)'),
    )
    STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('closed', 'Resolved'),
    )
    PRIORITY_CHOICES = (
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
    )

    TAGS_CHOICES = (
        ('electrical', 'Electrical'),
        ('mechanical', 'Mechanical'),
        ('maintenance', 'Maintenance'),
        ('packaging', 'Packaging'),
        ('logistics_and_supply', 'Logistics and Supply'),
        ('chain', 'Chain'),
        ('warehouse', 'Warehouse'),
        ('utilities', 'Utilities (Water, Electricity, HVAC, Steam)'),
        ('it_automation', 'IT/Automation'),
        ('civil_structural', 'CIVIL/Structural'),
        ('pest', 'Pest'),
        ('control', 'Control'),
        ('sanitation_and_hygiene', 'Sanitation and Hygiene'),
        ('calibration', 'Calibration'),
        ('energy', 'Energy'),
        ('management', 'Management'),
        ('process', 'Process'),
        ('improvement', 'Improvement'),
        ('training_and_development', 'Training and Development'),
        ('other', 'Other'),  # Add an "Other" option
    )

    AREAS_CHOICES = (
        ('cimbria_plant', 'Cimbria Plant'),
        ('buhler_plant', 'Buhler Plant'),
        ('raw_material_warehouse', 'Raw Material Warehouse'),
        ('finished_goods_warehouse', 'Finished Goods Warehouse'),
        ('by_product_warehouse', 'By-Product Warehouse'),
        ('packaging_and_maintenance_warehouse', 'Packaging and Maintenance Warehouse'),
        ('external_warehouse', 'External Warehouse'),
        ('mbp', 'MPB'),
        ('old_admin', 'Old Admin'),
        ('grain_unloading_area', 'Grain Unloading Area'),
        ('gate', 'Gate'),
        ('parking_lot', 'Parking Lot'),
        ('waste_collection_area', 'Waste Collection Area'),
        ('utilities', 'Utilities'),
        ('forklift_and_pallet_truck_garage', 'Forklift and Pallet Truck Garage'),
        ('plant_periphery', 'Plant Periphery'),
        ('other', 'Other'),  # Add an "Other" option
    )

    reporter = models.ForeignKey(User, on_delete=models.CASCADE, related_name='reported_observations', blank=True,
                                 null=True)
    department = models.CharField(max_length=100)
    date = models.DateField()
    time = models.TimeField()
    groupMembers_tags = models.JSONField(default=list)
    nature_of_issue = models.TextField()
    issue_type = models.CharField(max_length=20, choices=ISSUE_TYPES)
    corrective_action = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    priority = models.CharField(max_length=10, choices=PRIORITY_CHOICES, default='medium')

    # Modified fields to allow custom input
    area = models.CharField(max_length=100, choices=AREAS_CHOICES, default='other')
    area_custom = models.CharField(max_length=100, blank=True, default='')
    tags = models.CharField(max_length=100, choices=TAGS_CHOICES, default='other')
    tags_custom = models.CharField(max_length=100, blank=True, default='')

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    search_vector = SearchVectorField(null=True)
    location_details = models.TextField(blank=True)

    class Meta:
        indexes = [GinIndex(fields=['search_vector'])]
        permissions = [
            ("can_view_all_observations", "Can view all observations"),
            ("can_edit_observations", "Can edit observations"),
            ("can_delete_observations", "Can delete observations"),
            ("can_change_status", "Can change observation status"),
        ]

    def __str__(self):
        if self.reporter:
            return f"Observed by {self.reporter.get_username()} on {self.date}"
        return f"Observation on {self.date}"

    def get_tagged_members(self):
        return self.groupMembers_tags or []

    def get_area_display(self):
        """Returns the custom area if specified, otherwise returns the choice display value"""
        if self.area == 'other' and self.area_custom:
            return self.area_custom
        return dict(self.AREAS_CHOICES).get(self.area, self.area)

    def get_tags_display(self):
        """Returns the custom tags if specified, otherwise returns the choice display value"""
        if self.tags == 'other' and self.tags_custom:
            return self.tags_custom
        return dict(self.TAGS_CHOICES).get(self.tags, self.tags)


class ObservationAttachment(models.Model):
    observation = models.ForeignKey(SHEObservation, related_name='attachments', on_delete=models.CASCADE)
    file = models.FileField(
        upload_to='observation_attachments/%Y/%m/',
        validators=[
            FileExtensionValidator(
                allowed_extensions=['jpg', 'jpeg', 'png', 'pdf', 'doc', 'docx']
            )
        ]
    )
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Attachment for {self.observation} - {self.file.name}"

    def get_file_extension(self):
        """Get the file extension in lowercase"""
        name, extension = os.path.splitext(self.file.name)
        return extension.lower()[1:]  # Remove the dot and convert to lowercase

    def is_image(self):
        """Check if the file is an image"""
        return self.get_file_extension() in ['jpg', 'jpeg', 'png']

    def get_file_type_icon(self):
        """Return appropriate icon class based on file type"""
        ext = self.get_file_extension()
        if ext in ['jpg', 'jpeg', 'png']:
            return 'fa-image'
        elif ext == 'pdf':
            return 'fa-file-pdf'
        elif ext in ['doc', 'docx']:
            return 'fa-file-word'
        return 'fa-file'

    class Meta:
        ordering = ['-uploaded_at']


class ObservationAnalytics(models.Model):
    # Existing fields
    date = models.DateField(auto_now_add=True)
    department = models.CharField(max_length=100)
    total_observations = models.IntegerField(default=0)
    open_observations = models.IntegerField(default=0)
    closed_observations = models.IntegerField(default=0)
    average_resolution_time = models.DurationField(null=True)
    recurring_issues = models.TextField(blank=True)

    # New fields for storing detailed analytics
    issue_type_distribution = models.JSONField(default=dict)  # Stores count by issue type
    priority_distribution = models.JSONField(default=dict)  # Stores count by priority
    status_distribution = models.JSONField(default=dict)  # Stores count by status
    area_distribution = models.JSONField(default=dict)  # Stores count by area

    # Time-based metrics
    daily_counts = models.JSONField(default=dict)  # Stores daily observation counts
    weekly_counts = models.JSONField(default=dict)  # Stores weekly observation counts
    monthly_counts = models.JSONField(default=dict)  # Stores monthly observation counts

    # Performance metrics
    resolution_time_by_priority = models.JSONField(default=dict)  # Average resolution time per priority
    monthly_resolution_times = models.JSONField(default=dict)  # Monthly average resolution times

    # Comparative metrics
    department_comparison = models.JSONField(default=dict)  # Metrics compared across departments
    issue_type_by_department = models.JSONField(default=dict)  # Issue distribution by department

    class Meta:
        verbose_name_plural = "Observation Analytics"
        unique_together = ['date', 'department']  # Ensures one record per department per day

    def get_recurring_issues(self):
        """Returns recurring issues as a Python list/dict"""
        return json.loads(self.recurring_issues) if self.recurring_issues else []

    def set_recurring_issues(self, issues):
        """Stores recurring issues as JSON string"""
        self.recurring_issues = json.dumps(issues)

    def update_distributions(self, analytics_data):
        """Updates all distribution fields with new analytics data"""
        self.issue_type_distribution = analytics_data['issue_types_distribution']
        self.priority_distribution = analytics_data['priority_distribution']
        self.status_distribution = analytics_data['status_distribution']
        self.area_distribution = analytics_data['area_distribution']

    def update_time_based_metrics(self, analytics_data):
        """Updates all time-based metric fields"""
        self.daily_counts = analytics_data['time_series']['daily']
        self.weekly_counts = analytics_data['time_series']['weekly']
        self.monthly_counts = analytics_data['monthly_trend']

    def update_performance_metrics(self, analytics_data):
        """Updates all performance metric fields"""
        self.resolution_time_by_priority = analytics_data['average_resolution_by_priority']
        self.monthly_resolution_times = analytics_data['performance']['resolution_time_trend']

    def update_comparative_metrics(self, analytics_data):
        """Updates all comparative metric fields"""
        self.department_comparison = analytics_data['comparative']['department_comparison']
        self.issue_type_by_department = analytics_data['comparative']['issue_type_by_department']

class AuditTrail(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    action = models.CharField(max_length=255)
    timestamp = models.DateTimeField(auto_now_add=True)
    observation = models.ForeignKey(SHEObservation, on_delete=models.CASCADE)
    ip_address = models.GenericIPAddressField(null=True)
    user_agent = models.CharField(max_length=255, null=True)
    changes = models.JSONField(default=dict)  # Store what changed

    class Meta:
        ordering = ['-timestamp']
        permissions = [
            ("can_view_audit_trail", "Can view audit trail"),
        ]

    def __str__(self):
        return f"{self.user.username} - {self.action} - {self.timestamp}"


class NotificationPreference(models.Model):
    """User notification preferences"""
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    email_notifications = models.BooleanField(default=True)
    push_notifications = models.BooleanField(default=True)
    reminder_frequency = models.IntegerField(
        default=1,
        validators=[MinValueValidator(1), MaxValueValidator(30)]
    )
    notify_on_assignment = models.BooleanField(default=True)
    notify_on_status_change = models.BooleanField(default=True)
    notify_before_deadline = models.BooleanField(default=True)
    deadline_reminder_days = models.IntegerField(default=2)


class Notification(models.Model):
    """Store notifications"""
    NOTIFICATION_TYPES = [
        ('assignment', 'New Assignment'),
        ('status_change', 'Status Change'),
        ('deadline_approaching', 'Deadline Approaching'),
        ('overdue', 'Overdue Task'),
        ('comment', 'New Comment'),
        ('mentioned', 'Mentioned in Comment')
    ]

    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    notification_type = models.CharField(max_length=20, choices=NOTIFICATION_TYPES)
    title = models.CharField(max_length=200)
    message = models.TextField()
    related_observation = models.ForeignKey(
        'SHEObservation',
        on_delete=models.CASCADE,
        null=True
    )
    created_at = models.DateTimeField(auto_now_add=True)
    read = models.BooleanField(default=False)
    emailed = models.BooleanField(default=False)

    def send_email_notification(self):
        if self.user.notificationpreference.email_notifications:
            context = {
                'user': self.user,
                'notification': self,
                'observation': self.related_observation
            }

            html_message = render_to_string(
                'notifications/email_template.html',
                context
            )

            send_mail(
                subject=self.title,
                message=self.message,
                from_email=settings.EMAIL_HOST_USER,
                recipient_list=[self.user.email],
                html_message=html_message
            )
            self.emailed = True
            self.save()


class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    phone = models.CharField(max_length=20, blank=True)
    bio = models.TextField(max_length=500, blank=True)
    profile_image = models.ImageField(upload_to='profile_images/', null=True, blank=True)
    timezone = models.CharField(max_length=50, default='UTC')
    language = models.CharField(max_length=10, default='en')
    email_notifications = models.BooleanField(default=True)
    push_notifications = models.BooleanField(default=True)

    def __str__(self):
        return f'{self.user.username} Profile'


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
        ('completed', 'Completed'),
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
    completion_notes = models.TextField(blank=True)
    completion_date = models.DateField(null=True, blank=True)
    time_to_completion = models.DurationField(null=True, blank=True)
    # priority_level = models.CharField(max_length=10, choices=SHEObservation.PRIORITY_CHOICES)
    priority_level = models.CharField(
        max_length=10,
        choices=SHEObservation.PRIORITY_CHOICES,
        default='medium',  # Set a default value
        verbose_name="Priority Level"
    )

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
        permissions = [
            ("can_mark_complete", "Can mark actions as complete"),
            ("can_reassign", "Can reassign actions"),
            ("can_modify_deadline", "Can modify deadline"),
        ]


# class ObservationAttachment(models.Model):
#     observation = models.ForeignKey(
#         SHEObservation,
#         on_delete=models.CASCADE,
#         related_name='observation_attachments'
#     )
#     file = models.FileField(upload_to='observations/')
#     uploaded_at = models.DateTimeField(auto_now_add=True)
#
#     def __str__(self):
#         return f"Attachment for {self.observation}"
#
#     class Meta:
#         verbose_name = "Observation Attachment"
#         verbose_name_plural = "Observation Attachments"


