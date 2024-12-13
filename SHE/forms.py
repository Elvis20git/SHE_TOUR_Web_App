import os

from django import forms
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.contrib.auth import get_user_model
import random
import string
import logging
from django.urls import reverse_lazy
from .fields import MultipleFileInput, MultipleFileField
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.core.validators import FileExtensionValidator
from SHE.models import (
    Feedback,
    SHEObservation,
    CustomUser,
    ObservationActionTracking,
    NotificationPreference,
    Notification, ObservationAttachment
)
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import get_user_model
from django import forms
import string
import random


class CustomUserRegistrationForm(UserCreationForm):
    first_name = forms.CharField(widget=forms.TextInput(
        attrs={'class': 'form-control input-shadow', 'placeholder': 'Enter First Name', 'id': 'exampleInputFirstName'}
    ))
    last_name = forms.CharField(widget=forms.TextInput(
        attrs={'class': 'form-control input-shadow', 'placeholder': 'Enter Last Name', 'id': 'exampleInputLastName'}
    ))
    username = forms.CharField(widget=forms.TextInput(
        attrs={'class': 'form-control input-shadow', 'placeholder': 'Enter Username', 'id': 'exampleInputName'}
    ))
    email = forms.EmailField(widget=forms.EmailInput(
        attrs={'class': 'form-control input-shadow', 'placeholder': 'Enter Your Email ID', 'id': 'exampleInputEmailId'}
    ))
    department = forms.CharField(widget=forms.TextInput(
        attrs={'class': 'form-control input-shadow', 'placeholder': 'Enter Department', 'id': 'exampleInputDepartment'}
    ))
    role = forms.ChoiceField(
        choices=[('user', 'User'), ('manager', 'Manager'), ('administrator', 'Administrator')],
        widget=forms.Select(attrs={'class': 'form-control input-shadow', 'id': 'exampleInputRole'})
    )
    is_HOD=forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={
            'class': 'icheck-material-white',
            'id': 'is-HOD-checkbox'
        }))

    # Changed to PasswordInput for better security
    password1 = forms.CharField(widget=forms.TextInput(
        attrs={
            'class': 'form-control input-shadow',
            'placeholder': 'Generated Password',
            'id': 'exampleInputPassword',
            'readonly': 'readonly'
        }
    ))
    password2 = forms.CharField(widget=forms.TextInput(
        attrs={
            'class': 'form-control input-shadow',
            'placeholder': 'Confirm Password',
            'id': 'exampleInputConfirmPassword',
            'readonly': 'readonly'
        }
    ))

    account_activation = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={
            'class': 'icheck-material-white',
            'id': 'user-activation-checkbox'
        })
    )

    email_notifications = forms.BooleanField(
        initial=True,
        required=False,
        widget=forms.CheckboxInput(attrs={
            'class': 'icheck-material-white',
            'id': 'email-notifications-checkbox'
        })
    )

    reminder_frequency = forms.IntegerField(
        required=False,
        initial=1,
        min_value=1,
        max_value=30,
        widget=forms.NumberInput(attrs={
            'class': 'form-control input-shadow',
            'placeholder': 'Reminder Frequency (days)',
            'id': 'exampleInputReminderFreq'
        })
    )

    class Meta:
        model = get_user_model()
        fields = [
            'first_name', 'last_name', 'username', 'email',
            'department', 'role', 'password1', 'password2',
            'account_activation', 'email_notifications',
            'reminder_frequency', 'is_HOD'
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        random_password = self.generate_random_password()
        self.random_password = random_password  # Store the generated password
        self.fields['password1'].initial = random_password
        self.fields['password2'].initial = random_password

    def generate_random_password(self):
        """Generate a random password with letters, digits, and punctuation"""
        characters = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choice(characters) for i in range(12))

    def clean(self):
        """Validate form data"""
        cleaned_data = super().clean()

        # Ensure reminder_frequency is present and valid
        reminder_frequency = cleaned_data.get('reminder_frequency')
        if reminder_frequency is None:
            self.add_error('reminder_frequency', 'This field is required')
        elif reminder_frequency < 1 or reminder_frequency > 30:
            self.add_error('reminder_frequency', 'Must be between 1 and 30 days')

        return cleaned_data

    def save(self, commit=True):
        """Save the user and create notification preferences"""
        user = super().save(commit=False)
        user.email = self.cleaned_data['email']
        user.first_name = self.cleaned_data['first_name']
        user.last_name = self.cleaned_data['last_name']
        user.email_notifications = self.cleaned_data['email_notifications']
        user.reminder_frequency = self.cleaned_data['reminder_frequency']
        user.department = self.cleaned_data['department']
        user.role = self.cleaned_data['role']
        user.is_active = self.cleaned_data['account_activation']

        if commit:
            user.save()
            # Create notification preferences
            NotificationPreference.objects.create(
                user=user,
                email_notifications=user.email_notifications,
                reminder_frequency=user.reminder_frequency
            )
        return user



logger = logging.getLogger(__name__)


class CustomLoginForm(AuthenticationForm):
    username = forms.CharField(widget=forms.TextInput(
        attrs={'class': 'form-control input-shadow', 'placeholder': 'Enter Username', 'id': 'exampleInputUsername'}
    ))
    password = forms.CharField(widget=forms.PasswordInput(
        attrs={'class': 'form-control input-shadow', 'placeholder': 'Enter Password', 'id': 'exampleInputPassword'}
    ))
    remember_me = forms.BooleanField(required=False, initial=True, widget=forms.CheckboxInput(
        attrs={'class': 'icheck-material-white', 'id': 'user-checkbox'}
    ))

    def clean(self):
        try:
            username = self.cleaned_data.get('username')
            password = self.cleaned_data.get('password')

            if not username:
                raise ValidationError({
                    'username': 'Username is required.'
                })

            if not password:
                raise ValidationError({
                    'password': 'Password is required.'
                })

            try:
                user = CustomUser.objects.get(username=username)

                if not user.is_active:
                    raise ValidationError({
                        'username': 'This account is inactive.'
                    })

            except CustomUser.DoesNotExist:
                raise ValidationError({
                    '__all__': 'Invalid username or password.'
                })

            cleaned_data = super().clean()
            return cleaned_data

        except ValidationError as ve:
            logger.error(f"Validation error during login: {str(ve)}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during login validation: {str(e)}", exc_info=True)
            raise ValidationError("An unexpected error occurred during login.")

    class Meta:
        model = CustomUser
        fields = ['username', 'password', 'remember_me']



class FeedbackForm(forms.ModelForm):
    class Meta:
        model = Feedback
        fields = ['content']
        widgets = {
            'content': forms.Textarea(attrs={'rows': 4}),
        }



class MultipleFileInput(forms.ClearableFileInput):
    allow_multiple_selected = True

class MultipleFileField(forms.FileField):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault("widget", MultipleFileInput())
        validators = kwargs.get('validators', [])
        validators.append(FileExtensionValidator(
            allowed_extensions=['jpg', 'jpeg', 'png', 'pdf', 'doc', 'docx']
        ))
        kwargs['validators'] = validators
        super().__init__(*args, **kwargs)

    def clean(self, data, initial=None):
        single_file_clean = super().clean
        if isinstance(data, (list, tuple)):
            result = [single_file_clean(d, initial) for d in data]
        else:
            result = single_file_clean(data, initial)
        return result

class SHEObservationForm(forms.ModelForm):
    group_members = forms.ModelMultipleChoiceField(
        queryset=get_user_model().objects.all(),
        required=False,
        widget=forms.SelectMultiple(attrs={
            'class': 'select2-users',
            'data-placeholder': 'Search and select team members...',
        })
    )

    groupMembers_tags = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter member tags (comma-separated)',
            'data-role': 'tagsinput'
        })
    )

    # Modified area field to use Select2 with custom input
    area = forms.ChoiceField(
        choices=SHEObservation.AREAS_CHOICES,
        required=True,
        widget=forms.Select(attrs={
            'class': 'form-control select2-with-custom-input',
            'data-placeholder': 'Select or enter area...',
        })
    )

    area_custom = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter custom area',
            'style': 'display: none;'  # Initially hidden
        })
    )

    # Modified tags field to use Select2 with custom input
    tags = forms.ChoiceField(
        choices=SHEObservation.TAGS_CHOICES,
        required=True,
        widget=forms.Select(attrs={
            'class': 'form-control select2-with-custom-input',
            'data-placeholder': 'Select or enter tags...',
        })
    )

    tags_custom = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter custom tags',
            'style': 'display: none;'  # Initially hidden
        })
    )

    location_details = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'placeholder': 'Enter detailed location information',
            'rows': 3
        })
    )

    attachments = MultipleFileField(
        required=False,
        help_text='Upload files (jpg, jpeg, png, pdf, doc, docx)',
        widget=MultipleFileInput(attrs={
            'class': 'form-control',
            'accept': '.pdf,.doc,.docx,.jpg,.jpeg,.png'
        })
    )


    class Meta:
        model = SHEObservation
        fields = [
            'department', 'date', 'time', 'area', 'area_custom',
            'nature_of_issue', 'issue_type', 'corrective_action',
            'priority', 'tags', 'tags_custom', 'location_details', 'attachments',
            'group_members', 'groupMembers_tags'
        ]
        widgets = {
            'department': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter Department'}),
            'date': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'time': forms.TimeInput(attrs={'class': 'form-control', 'type': 'time'}),
            'nature_of_issue': forms.Textarea(
                attrs={'class': 'form-control', 'placeholder': 'Describe the nature of the issue'}),
            'issue_type': forms.Select(attrs={'class': 'form-control'}),
            'corrective_action': forms.Textarea(
                attrs={'class': 'form-control', 'placeholder': 'Describe the corrective action'}),
            'priority': forms.Select(attrs={'class': 'form-control'}),
        }

    def clean(self):
        cleaned_data = super().clean()

        # Validate area field
        area = cleaned_data.get('area')
        area_custom = cleaned_data.get('area_custom')

        if area == 'other' and not area_custom:
            self.add_error('area_custom', 'Please enter a custom area when selecting Other')

        # Validate tags field
        tags = cleaned_data.get('tags')
        tags_custom = cleaned_data.get('tags_custom')

        if tags == 'other' and not tags_custom:
            self.add_error('tags_custom', 'Please enter custom tags when selecting Other')

        return cleaned_data

    def clean_groupMembers_tags(self):
        """Convert comma-separated tags to a list for JSON storage"""
        tags_str = self.cleaned_data.get('groupMembers_tags', '')
        if tags_str:
            tags_list = [tag.strip() for tag in tags_str.split(',') if tag.strip()]
            return tags_list
        return []

    def clean_attachments(self):
        """Validate the uploaded files"""
        files = self.files.getlist('attachments')
        if files:
            for file in files:
                if file.size > 5 * 1024 * 1024:
                    raise ValidationError(f'File {file.name} is too large. Maximum size is 5MB.')

                allowed_extensions = ['.pdf', '.doc', '.docx', '.jpg', '.jpeg', '.png']
                ext = os.path.splitext(file.name)[1].lower()
                if ext not in allowed_extensions:
                    raise ValidationError(
                        f'Invalid file type for {file.name}. Allowed types are: {", ".join(allowed_extensions)}'
                    )
        return files

    def save(self, commit=True):
        """Save the form and handle file attachments"""
        instance = super().save(commit=False)

        # Set groupMembers_tags from cleaned data
        instance.groupMembers_tags = self.cleaned_data.get('groupMembers_tags', [])

        if commit:
            instance.save()
            self.save_m2m()

            # Handle file attachments
            files = self.files.getlist('attachments')
            for file in files:
                ObservationAttachment.objects.create(
                    observation=instance,
                    file=file
                )

        return instance

class ObservationActionTrackingForm(forms.ModelForm):
    completion_notes = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'placeholder': 'Enter completion notes',
            'rows': 3
        })
    )

    class Meta:
        model = ObservationActionTracking
        fields = [
            'date', 'she_observation', 'action',
            'assign_to', 'deadline', 'status',
            'priority_level', 'completion_notes'
        ]
        widgets = {
            'date': forms.DateInput(attrs={
                'type': 'date',
                'class': 'form-control'
            }),
            'she_observation': forms.Select(attrs={
                'class': 'form-control'
            }),
            'action': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3
            }),
            'assign_to': forms.Select(attrs={
                'class': 'form-control'
            }),
            'deadline': forms.DateInput(attrs={
                'type': 'date',
                'class': 'form-control'
            }),
            'status': forms.Select(attrs={
                'class': 'form-control'
            }),
            'priority_level': forms.Select(attrs={
                'class': 'form-control'
            }),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['she_observation'].queryset = SHEObservation.objects.all().order_by('nature_of_issue')
        self.fields['assign_to'].queryset = get_user_model().objects.filter(is_HOD=True).order_by('username')

        if self.instance.pk:
            # If editing existing instance
            self.fields['date'].widget.attrs['readonly'] = True
            self.fields['she_observation'].widget.attrs['readonly'] = True
            self.fields['date'].required = False
            self.fields['she_observation'].required = False

            # Store original values
            self.initial_she_observation = self.instance.she_observation
            self.initial_date = self.instance.date

            # Make completion notes required if status is completed
            if self.instance.status == 'completed':
                self.fields['completion_notes'].required = True

    def clean(self):
        cleaned_data = super().clean()
        status = cleaned_data.get('status')
        completion_notes = cleaned_data.get('completion_notes')
        deadline = cleaned_data.get('deadline')

        # Validate completion notes when status is completed
        if status == 'completed' and not completion_notes:
            self.add_error('completion_notes', 'Completion notes are required when status is completed')

        # Preserve original values in update mode
        if hasattr(self, 'initial_she_observation'):
            cleaned_data['she_observation'] = self.initial_she_observation
            cleaned_data['date'] = self.initial_date

        # Check deadline
        if deadline and deadline <= timezone.now().date() and status in ['pending', 'in_progress']:
            cleaned_data['status'] = 'overdue'

        return cleaned_data


class NotificationPreferenceForm(forms.ModelForm):
    class Meta:
        model = NotificationPreference
        fields = [
            'email_notifications',
            'push_notifications',
            'reminder_frequency',
            'notify_on_assignment',
            'notify_on_status_change',
            'notify_before_deadline',
            'deadline_reminder_days'
        ]
        widgets = {
            'email_notifications': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'push_notifications': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'reminder_frequency': forms.NumberInput(attrs={'class': 'form-control'}),
            'notify_on_assignment': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'notify_on_status_change': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'notify_before_deadline': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'deadline_reminder_days': forms.NumberInput(attrs={'class': 'form-control'}),
        }


class FeedbackForm(forms.ModelForm):
    class Meta:
        model = Feedback
        fields = ['content']
        widgets = {
            'content': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 4,
                'placeholder': 'Enter your feedback here'
            }),
        }