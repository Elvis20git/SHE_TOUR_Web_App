from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.views import View
from django.views.decorators.cache import cache_page
from django.views.generic import ListView, DetailView, CreateView, UpdateView, DeleteView
from django.urls import reverse_lazy
from django.contrib import messages
from django.db.models import Q, Count
from django.utils import timezone
from django.core.paginator import Paginator
from django.http import JsonResponse, HttpResponseForbidden, HttpResponseRedirect
from django.views.decorators.http import require_POST
from django.utils.decorators import method_decorator
from django.contrib.auth.views import LoginView
from django.core.exceptions import PermissionDenied
import json
from django.core.serializers.json import DjangoJSONEncoder
import logging
from django.core.exceptions import PermissionDenied
from datetime import timedelta
from django.contrib.auth import get_user_model, logout
from django.db.models.functions import TruncDate
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth import update_session_auth_hash
import pytz
from .forms import (
    CustomLoginForm, CustomUserRegistrationForm, SHEObservationForm,
    ObservationActionTrackingForm, NotificationPreferenceForm, FeedbackForm
)
from .models import (
    CustomUser, SHEObservation, ObservationActionTracking,
    NotificationPreference, Notification, ObservationAttachment,
    AuditTrail, ObservationAnalytics, Feedback, Profile
)
from .tasks import send_welcome_email
from django.contrib.auth import login as auth_login
from django.contrib.auth.views import (
    PasswordResetView,
    PasswordResetDoneView,
    PasswordResetConfirmView,
    PasswordResetCompleteView
)
from django.db.models import Count
from datetime import datetime



logger = logging.getLogger(__name__)
class CustomLoginView(LoginView):
    form_class = CustomLoginForm
    template_name = 'registration/login.html'
    redirect_authenticated_user = True

    def form_valid(self, form):
        """Security check complete. Log the user in."""
        logger.info(f"Form validation successful for user: {form.cleaned_data['username']}")
        auth_login(self.request, form.get_user())

        if self.request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({
                'success': True,
                'redirect_url': self.get_success_url()
            })
        return HttpResponseRedirect(self.get_success_url())

    def form_invalid(self, form):
        """If the form is invalid, render the invalid form."""
        logger.warning(f"Form validation failed: {form.errors}")

        if self.request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({
                'success': False,
                'message': 'Invalid username or password.',
                'errors': form.errors
            }, status=400)
        return self.render_to_response(self.get_context_data(form=form))

    def get_success_url(self):
        logger.info(f"Getting success URL for user {self.request.user}")
        return reverse_lazy('analytics_dashboard')

    def get(self, request, *args, **kwargs):
        if self.request.user.is_authenticated:
            logger.info(
                f"Already authenticated user {self.request.user} accessing login page - redirecting to dashboard")
            return redirect(self.get_success_url())
        return super().get(request, *args, **kwargs)


logger = logging.getLogger(__name__)

class CustomUserRegistrationView(CreateView):
    """
    View for user self-registration.
    """
    model = CustomUser
    form_class = CustomUserRegistrationForm
    template_name = 'registration/register.html'
    success_url = reverse_lazy('login')

    def form_valid(self, form):
        """
        Process the valid form data and create the user.
        """
        logger.debug(f"Processing valid form data: {form.cleaned_data}")
        try:
            # Create the user
            user = form.save()
            logger.info(f"New user created successfully: {user.username}")

            # Send welcome email using Celery
            if user.is_active:
                send_welcome_email.delay(
                    username=user.username,
                    email=user.email,
                    password=form.random_password
                )
                logger.info(f"Welcome email task queued for {user.email}")

            messages.success(
                self.request,
                'Account created successfully! Please check your email for login credentials.'
            )
            return redirect(self.success_url)

        except Exception as e:
            logger.error("Error creating user", exc_info=True)
            messages.error(
                self.request,
                f"Failed to create account: {str(e)}"
            )
            return self.form_invalid(form)

    def form_invalid(self, form):
        """
        Handle invalid form submission.
        """
        logger.warning(f"Form validation failed. Errors: {form.errors}")
        for field, errors in form.errors.items():
            for error in errors:
                messages.error(self.request, f"{field}: {error}")
        return super().form_invalid(form)

    def get_context_data(self, **kwargs):
        """
        Add extra context data for the template.
        """
        context = super().get_context_data(**kwargs)
        context.update({
            'title': 'Create Account',
            'submit_text': 'Register',
        })
        logger.debug(f"Template context: {context}")
        return context





# Dashboard Views

def dashboard(request):
    # Get date range (last 30 days)
    end_date = timezone.now().date()
    start_date = end_date - timedelta(days=29)

    # Get observations data grouped by date
    daily_observations = (
        SHEObservation.objects
        .filter(date__range=[start_date, end_date])
        .annotate(date=TruncDate('created_at'))
        .values('date')
        .annotate(
            new_count=Count('id'),
            resolved_count=Count('id', filter=Q(status='closed'))
        )
        .order_by('date')
    )

    # Prepare data for charts
    dates = []
    new_observations = []
    resolved_observations = []

    current_date = start_date
    while current_date <= end_date:
        dates.append(current_date.strftime('%Y-%m-%d'))
        day_data = next(
            (item for item in daily_observations if item['date'].date() == current_date),
            {'new_count': 0, 'resolved_count': 0}
        )
        new_observations.append(day_data['new_count'])
        resolved_observations.append(day_data['resolved_count'])
        current_date += timedelta(days=1)

    # Get issue types data
    issue_types_data = (
        SHEObservation.objects
        .values('issue_type')
        .annotate(count=Count('id'))
        .order_by('issue_type')
    )

    # Calculate percentages for issue types
    total_issues = sum(item['count'] for item in issue_types_data)
    issue_type_percentages = {
        item['issue_type']: (item['count'] / total_issues * 100) if total_issues > 0 else 0
        for item in issue_types_data
    }

    # Department wise analysis
    department_data = (
        SHEObservation.objects
        .values('department')
        .annotate(
            total=Count('id'),
            high_priority=Count('id', filter=Q(priority='high')),
            resolved=Count('id', filter=Q(status='closed'))
        )
        .order_by('-total')
    )

    context = {
        # Basic statistics
        'total_observations': SHEObservation.objects.count(),
        'pending_observations': SHEObservation.objects.filter(status='pending').count(),
        'high_priority_count': SHEObservation.objects.filter(priority='high').count(),
        'resolved_count': SHEObservation.objects.filter(status='closed').count(),

        # Recent observations
        'recent_observations': SHEObservation.objects.order_by('-date')[:10],

        # Chart data
        'dates': json.dumps(dates),
        'new_observations_data': json.dumps(new_observations),
        'resolved_observations_data': json.dumps(resolved_observations),

        # Issue types data
        'issue_types_data': json.dumps({
            'labels': list(issue_type_percentages.keys()),
            'data': list(issue_type_percentages.values())
        }),

        # Department data
        'department_data': json.dumps([{
            'department': item['department'],
            'total': item['total'],
            'high_priority': item['high_priority'],
            'resolved': item['resolved']
        } for item in department_data])

    }


    return render(request, 'analytics/analytics.html', context)









class ObservationListView(LoginRequiredMixin, ListView):
    model = SHEObservation
    template_name = 'observations/list.html'
    context_object_name = 'observations'
    paginate_by = 10
    # login_url = 'login'

    def get_queryset(self):
        queryset = SHEObservation.objects.all()

        # Role-based filtering
        user = self.request.user
        if user.role == 'user':  # Assuming you have a role field in your User model
            # Regular users can only see:
            # 1. Observations they reported
            # 2. Observations in their department
            queryset = queryset.filter(
                Q(reporter=user) |
                Q(department=user.department)
            )
        # Managers and admins can see all observations
        # No filtering needed for them

        # Search functionality
        search_query = self.request.GET.get('search')
        if search_query:
            queryset = queryset.filter(
                Q(nature_of_issue__icontains=search_query) |
                Q(department__icontains=search_query) |
                Q(tags__icontains=search_query)
            )

        # Filter by status
        status_filter = self.request.GET.get('status')
        if status_filter:
            queryset = queryset.filter(status=status_filter)

        return queryset.order_by('-created_at')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # Only provide all observations count to managers and admins
        if self.request.user.role in ['manager', 'admin']:
            context['allObservations'] = SHEObservation.objects.all()
        else:
            # For regular users, only show their related observations count
            context['allObservations'] = SHEObservation.objects.filter(
                Q(reporter=self.request.user) |
                Q(department=self.request.user.department)
            )
        return context


class ObservationDetailView(LoginRequiredMixin, DetailView):
    model = SHEObservation
    template_name = 'observations/detail.html'
    context_object_name = 'observation'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['tracking_entries'] = self.object.tracking_entries.all()
        context['attachments'] = self.object.observation_attachments.all()
        return context

def update_observation_status(request, observation_id):
    if request.method == 'POST':
        observation = get_object_or_404(SHEObservation, id=observation_id)
        new_status = request.POST.get('status')
        if new_status in ['open', 'in_progress', 'closed']:
            observation.status = new_status
            observation.save()
            messages.success(request, 'Status updated successfully.')
        else:
            messages.error(request, 'Invalid status value.')
    return redirect('observation_list')



User = get_user_model()

logger = logging.getLogger(__name__)

# 
class SHEObservationCreateView(LoginRequiredMixin, CreateView):
    model = SHEObservation
    form_class = SHEObservationForm
    template_name = 'observations/observation.html'
    success_url = reverse_lazy('observation_list')

    def form_valid(self, form):
        try:
            # Get the selected members data from the hidden input
            selected_members_json = self.request.POST.get('selected_members', '[]')
            try:
                selected_members = json.loads(selected_members_json)
            except json.JSONDecodeError:
                selected_members = []

            # Don't save the form yet
            self.object = form.save(commit=False)
            self.object.reporter = self.request.user

            # Handle area field
            area = form.cleaned_data.get('area')
            area_custom = form.cleaned_data.get('area_custom')
            if area not in dict(SHEObservation.AREAS_CHOICES) and area_custom:
                self.object.area = 'other'
                self.object.area_custom = area_custom
            else:
                self.object.area = area
                self.object.area_custom = ''

            # Handle tags field
            tags = form.cleaned_data.get('tags')
            tags_custom = form.cleaned_data.get('tags_custom')
            if tags and tags not in dict(SHEObservation.TAGS_CHOICES):
                self.object.tags = 'other'
                self.object.tags_custom = tags_custom
            else:
                self.object.tags = tags
                self.object.tags_custom = ''

            # Handle groupMembers_tags - combine both sources
            group_members_tags = form.cleaned_data.get('groupMembers_tags', [])
            # Add names from selected members if they're not already in tags
            member_usernames = [member['username'] for member in selected_members]
            combined_tags = list(set(group_members_tags + member_usernames))

            # Store the combined tags
            self.object.groupMembers_tags = combined_tags

            # Save the observation
            self.object.save()

            # Save many-to-many relationships
            form.save_m2m()

            # Handle file attachments
            files = self.request.FILES.getlist('attachments')
            allowed_extensions = ['jpg', 'jpeg', 'png', 'pdf', 'doc', 'docx']

            for file in files:
                # Get file extension
                file_extension = file.name.split('.')[-1].lower()

                # Validate file extension
                if file_extension in allowed_extensions:
                    ObservationAttachment.objects.create(
                        observation=self.object,
                        file=file
                    )
                else:
                    messages.error(
                        self.request,
                        f'File {file.name} has an invalid extension. Allowed extensions are: {", ".join(allowed_extensions)}'
                    )

            # Create detailed changes dictionary
            changes = {
                'action_type': 'creation',
                'group_members_tags': {
                    'tags': combined_tags,
                    'selected_members': selected_members
                },
                'creation_details': {
                    'department': str(self.object.department),
                    'area': str(self.object.get_area_display()),  # Use the display method
                    'area_custom': str(self.object.area_custom) if self.object.area_custom else '',
                    'issue_type': str(self.object.issue_type),
                    'priority': str(self.object.priority),
                    'tags': str(self.object.get_tags_display()),  # Use the display method
                    'tags_custom': str(self.object.tags_custom) if self.object.tags_custom else '',
                    'attachments_count': len(files)
                }
            }

            # Create the audit trail
            AuditTrail.objects.create(
                user=self.request.user,
                action='created',
                observation=self.object,
                ip_address=self.request.META.get('REMOTE_ADDR'),
                user_agent=self.request.META.get('HTTP_USER_AGENT'),
                changes=changes
            )

            messages.success(self.request, 'Observation created successfully.')
            return HttpResponseRedirect(self.get_success_url())

        except json.JSONDecodeError as e:
            logger.error(f"Error parsing selected members JSON: {str(e)}")
            messages.error(self.request, 'Error processing member data. Please try again.')
            return self.form_invalid(form)
        except Exception as e:
            logger.error(f"Error creating observation: {str(e)}", exc_info=True)
            messages.error(self.request, 'An error occurred while creating the observation. Please try again.')
            return self.form_invalid(form)


# 
class ObservationUpdateView(LoginRequiredMixin, UserPassesTestMixin, UpdateView):
    model = SHEObservation
    form_class = SHEObservationForm
    template_name = 'observations/updateObservation.html'
    success_url = reverse_lazy('observation_list')

    def extract_username(self, tag):
        """Extract username from tag (e.g., 'Elvis_Murengerantwari_(Elvis123)' -> 'Elvis123')"""
        start = tag.find('(') + 1
        end = tag.find(')')
        if start > 0 and end > start:
            return tag[start:end]
        return tag

    def test_func(self):
        obj = self.get_object()
        is_authorized = (self.request.user.is_manager_or_above or
                         obj.reporter == self.request.user)

        if not is_authorized:
            logger.warning(
                f"Unauthorized update attempt for Observation {obj.id} by user {self.request.user}"
            )

        return is_authorized

    def handle_no_permission(self):
        messages.error(
            self.request,
            "You don't have permission to edit this observation. Only the reporter or managers can edit it."
        )
        return super().handle_no_permission()

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        observation = self.get_object()
        context['observation'] = observation

        # Extract usernames from tags
        if observation.groupMembers_tags:
            context['group_members_tags'] = [
                self.extract_username(tag) for tag in observation.groupMembers_tags
            ]
        else:
            context['group_members_tags'] = []

        context['tagged_members'] = []  # If you still need this

        return context

    def get_initial(self):
        """Set initial form data"""
        initial = super().get_initial()
        observation = self.get_object()

        # Convert list to comma-separated string for the form field
        if observation.groupMembers_tags:
            initial['groupMembers_tags'] = ','.join([
                self.extract_username(tag) for tag in observation.groupMembers_tags
            ])

        return initial

    def get_changes(self, form):
        """Track specific field changes for audit trail"""
        changes = {}
        if form.changed_data:
            for field in form.changed_data:
                old_value = getattr(self.get_object(), field)
                new_value = form.cleaned_data[field]

                # Special handling for groupMembers_tags
                if field == 'groupMembers_tags':
                    old_value = [self.extract_username(tag) for tag in (old_value or [])]
                    new_value = [self.extract_username(tag) for tag in (new_value or [])]

                if old_value != new_value:
                    changes[field] = {
                        'old': str(old_value),
                        'new': str(new_value)
                    }
        return changes

    def form_valid(self, form):
        try:
            # Get changes before saving
            changes = self.get_changes(form)

            # Save the form
            response = super().form_valid(form)

            # Handle file attachments
            attachments = self.request.FILES.getlist('attachments')
            for attachment in attachments:
                ObservationAttachment.objects.create(
                    observation=self.object,
                    file=attachment,
                    uploaded_by=self.request.user
                )

            # Create audit trail entry
            AuditTrail.objects.create(
                user=self.request.user,
                action='updated',
                observation=self.object,
                ip_address=self.request.META.get('REMOTE_ADDR'),
                user_agent=self.request.META.get('HTTP_USER_AGENT'),
                changes=changes
            )

            # Log the successful update
            logger.info(
                f"Observation {self.object.id} updated by {self.request.user} "
                f"with changes: {changes}"
            )

            messages.success(self.request, 'Observation updated successfully.')
            return response

        except Exception as e:
            logger.error(
                f"Error updating Observation {self.object.id}: {str(e)}",
                exc_info=True
            )
            messages.error(
                self.request,
                'An error occurred while updating the observation. Please try again.'
            )
            return self.form_invalid(form)

# Optional: Add a view to handle AJAX requests for tag management

# 
def manage_group_members_tags(request, observation_id):
    try:
        observation = get_object_or_404(SHEObservation, id=observation_id)
        action = request.POST.get('action')
        tags = json.loads(request.POST.get('tags', '[]'))

        if action == 'add':
            current_tags = observation.groupMembers_tags
            new_tags = list(set(current_tags + tags))
            observation.groupMembers_tags = new_tags
        elif action == 'remove':
            current_tags = observation.groupMembers_tags
            new_tags = [tag for tag in current_tags if tag not in tags]
            observation.groupMembers_tags = new_tags
        elif action == 'update':
            observation.groupMembers_tags = tags

        observation.save()

        # Create audit trail for tag changes
        AuditTrail.objects.create(
            user=request.user,
            action=f'modified_group_members_tags_{action}',
            observation=observation,
            ip_address=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT'),
            changes={'group_members_tags': {
                'action': action,
                'tags': tags
            }}
        )

        return JsonResponse({'success': True, 'tags': observation.groupMembers_tags})
    except Exception as e:
        logger.error(f"Error managing group members tags: {str(e)}", exc_info=True)
        return JsonResponse({'success': False, 'error': str(e)})


@require_POST
# 
def delete_attachment(request):
    """
    Delete an observation attachment
    """
    attachment_id = request.POST.get('attachment_id')
    try:
        # Get the attachment object instead of SHEObservation
        attachment = get_object_or_404(ObservationAttachment, id=attachment_id)

        # Optional: Add permission check
        if request.user == attachment.observation.reporter or request.user.is_manager_or_above:
            # Delete the actual file
            attachment.file.delete(save=False)
            # Delete the attachment record
            attachment.delete()
            return JsonResponse({'success': True})
        else:
            return JsonResponse({
                'success': False,
                'error': 'You do not have permission to delete this attachment'
            })
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})


# 
def user_search(request):
    """
    AJAX view for searching users with Select2
    Returns paginated results in Select2's expected format
    """
    User = get_user_model()
    term = request.GET.get('term', '')
    page = int(request.GET.get('page', 1))
    page_size = 10  # Number of results per page

    # Search in username, first_name, and last_name
    users = User.objects.filter(
        Q(username__icontains=term) |
        Q(first_name__icontains=term) |
        Q(last_name__icontains=term) |
        Q(email__icontains=term)
    ).distinct().order_by('first_name', 'last_name')

    # Calculate pagination
    total = users.count()
    start = (page - 1) * page_size
    end = start + page_size

    # Format results for Select2
    results = [
        {
            'id': user.id,
            'text': f"{user.get_full_name()} ({user.username})" if user.get_full_name() else user.username,
            # Optional: Add more user data if needed
            'email': user.email,
            'department': getattr(user, 'department', ''),  # If you have a department field
        }
        for user in users[start:end]
    ]

    # Return in Select2's expected format
    return JsonResponse({
        'results': results,
        'pagination': {
            'more': total > (page * page_size)  # True if there are more pages
        }
    })

# 
class ObservationDeleteView(LoginRequiredMixin, UserPassesTestMixin, DeleteView):
    model = SHEObservation
    success_url = reverse_lazy('observation_list')
    http_method_names = ['post']  # Only allow POST requests

    def test_func(self):
        obj = self.get_object()
        return obj.reporter == self.request.user

    def handle_no_permission(self):
        messages.error(
            self.request,
            "You don't have permission to delete this observation. Only the original reporter can delete it."
        )
        return redirect('observation_list')

    def post(self, request, *args, **kwargs):
        try:
            observation = self.get_object()

            # Create audit trail entry before deletion
            AuditTrail.objects.create(
                user=self.request.user,
                action='deleted',
                observation=observation,
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT')
            )

            # Perform the deletion
            observation.delete()

            messages.success(request, 'Observation deleted successfully.')
            return redirect('observation_list')

        except Exception as e:
            messages.error(request, 'An error occurred while deleting the observation.')
            return redirect('observation_list')










# Action Tracking Views
# 
class ActionTrackingCreateView(LoginRequiredMixin, UserPassesTestMixin, CreateView):
    model = ObservationActionTracking
    form_class = ObservationActionTrackingForm
    template_name = 'tracking/actionTracking.html'

    def test_func(self):
        return self.request.user.is_manager_or_above

    def get_success_url(self):
        return reverse_lazy('observation_detail',
                            kwargs={'pk': self.object.she_observation.pk})

    def form_valid(self, form):
        form.instance.she_observation_id = self.kwargs['observation_id']
        response = super().form_valid(form)

        # Create notification for assigned user
        if form.instance.assign_to:
            Notification.objects.create(
                user=form.instance.assign_to,
                notification_type='assignment',
                title='New Action Assigned',
                message=f'You have been assigned an action for observation {form.instance.she_observation}',
                related_observation=form.instance.she_observation
            )

        messages.success(self.request, 'Action tracking created successfully.')
        return response


# 
class ActionTrackingUpdateView(LoginRequiredMixin, UserPassesTestMixin, UpdateView):
    model = ObservationActionTracking
    form_class = ObservationActionTrackingForm
    template_name = 'tracking/update.html'

    def test_func(self):
        obj = self.get_object()
        return (self.request.user.is_manager_or_above or
                obj.assign_to == self.request.user)

    def get_success_url(self):
        return reverse_lazy('observation_detail',
                            kwargs={'pk': self.object.she_observation.pk})

    def form_valid(self, form):
        if 'status' in form.changed_data and form.instance.status == 'completed':
            form.instance.completion_date = timezone.now().date()
            form.instance.time_to_completion = (
                    timezone.now().date() - form.instance.date
            )

        response = super().form_valid(form)

        # Create notification for status change
        if 'status' in form.changed_data:
            Notification.objects.create(
                user=self.object.she_observation.reporter,
                notification_type='status_change',
                title='Action Status Updated',
                message=f'Action status updated to {self.object.get_status_display()}',
                related_observation=self.object.she_observation
            )

        messages.success(self.request, 'Action tracking updated successfully.')
        return response


# Notification Views

def notification_list(request):
    notifications = Notification.objects.filter(user=request.user) \
        .order_by('-created_at')
    unread_count = notifications.filter(read=False).count()

    paginator = Paginator(notifications, 10)
    page = request.GET.get('page')
    notifications = paginator.get_page(page)

    return render(request, 'notifications/list.html', {
        'notifications': notifications,
        'unread_count': unread_count
    })


@login_required
def mark_all_notifications_read(request):
    if request.method == 'POST':
        # Get all unread notifications for the current user
        notifications = Notification.objects.filter(
            user=request.user,
            read=False
        )

        # Update all notifications to read
        notifications.update(read=True)

        return JsonResponse({'success': True})

    return JsonResponse({'success': False}, status=400)


@login_required
def mark_notification_read(request):
    if request.method == 'POST':
        notification_id = request.POST.get('notification_id')

        try:
            notification = Notification.objects.get(
                id=notification_id,
                user=request.user
            )
            notification.read = True
            notification.save()

            return JsonResponse({'success': True})
        except Notification.DoesNotExist:
            return JsonResponse({'success': False}, status=404)

    return JsonResponse({'success': False}, status=400)


@login_required
def get_unread_count(request):
    """
    Returns the count of unread notifications for the current user.
    """
    count = Notification.objects.filter(
        user=request.user,
        read=False
    ).count()

    return JsonResponse({'count': count})

@require_POST
# 
def mark_notification_read(request, pk):
    notification = get_object_or_404(Notification, pk=pk, user=request.user)
    notification.read = True
    notification.save()
    return JsonResponse({'status': 'success'})


# User Profile and Settings Views
class NotificationPreferenceUpdateView(LoginRequiredMixin, UpdateView):
    model = NotificationPreference
    form_class = NotificationPreferenceForm
    template_name = 'profile/notification_preferences.html'
    success_url = reverse_lazy('profile')

    def get_object(self, queryset=None):
        return self.request.user.notificationpreference


# Profile Views

@login_required
def profile_view(request):
    user = CustomUser.objects.get(pk=request.user.pk)

    # Get actions assigned to user
    assigned_actions = ObservationActionTracking.objects.filter(assign_to=user)

    # Count statistics
    observations_count = assigned_actions.count()
    tasks_count = assigned_actions.exclude(status='completed').count()

    try:
        latest_analytics = ObservationAnalytics.objects.filter(
            department=user.department
        ).latest('date')
        comments_count = latest_analytics.daily_counts.get('comments', 0)
    except ObservationAnalytics.DoesNotExist:
        comments_count = 0

    context = {
        'user_full_name': f"{user.first_name} {user.last_name}",
        'observations_count': observations_count,
        'comments_count': comments_count,
        'tasks_count': tasks_count,
        'timezones': pytz.common_timezones,
        'languages': [
            ('en', 'English'),
            ('es', 'Spanish'),
            ('fr', 'French'),
        ],
        'assigned_actions': assigned_actions
    }

    # Add analytics if available
    if 'latest_analytics' in locals():
        context.update({
            'priority_distribution': latest_analytics.priority_distribution,
            'status_distribution': latest_analytics.status_distribution,
            'resolution_times': latest_analytics.resolution_time_by_priority,
            'monthly_trend': latest_analytics.monthly_counts
        })

    return render(request, 'profile/profile.html', context)


@login_required
def update_profile(request):
    """
    Handle user profile information updates.
    """
    if request.method == 'POST':
        try:
            # Update user information
            user = request.user
            user.first_name = request.POST.get('first_name', '')
            user.last_name = request.POST.get('last_name', '')

            # Update or create profile
            profile, created = Profile.objects.get_or_create(user=user)
            profile.phone = request.POST.get('phone', '')
            profile.bio = request.POST.get('bio', '')

            user.save()
            profile.save()

            messages.success(request, 'Profile updated successfully!')
        except Exception as e:
            messages.error(request, f'Error updating profile: {str(e)}')

        return redirect('profile')

    return redirect('profile')


@login_required
def update_settings(request):
    """
    Handle user settings updates (timezone, language, notifications).
    """
    if request.method == 'POST':
        try:
            profile, created = Profile.objects.get_or_create(user=request.user)

            # Update settings
            profile.timezone = request.POST.get('timezone', 'UTC')
            profile.language = request.POST.get('language', 'en')
            profile.email_notifications = request.POST.get('email_notifications') == 'on'
            profile.push_notifications = request.POST.get('push_notifications') == 'on'

            profile.save()
            messages.success(request, 'Settings updated successfully!')
        except Exception as e:
            messages.error(request, f'Error updating settings: {str(e)}')

        return redirect('profile')

    return redirect('profile')


@login_required
def change_password(request):
    """
    Handle password change.
    """
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            # Update session to prevent logout
            update_session_auth_hash(request, user)
            messages.success(request, 'Your password was successfully updated!')
        else:
            messages.error(request, 'Please correct the errors below.')

    return redirect('profile')


@login_required
def update_avatar(request):
    """
    Handle profile picture upload.
    """
    if request.method == 'POST' and request.FILES.get('avatar'):
        try:
            profile, created = Profile.objects.get_or_create(user=request.user)

            # Delete old avatar if it exists
            if profile.profile_image:
                profile.profile_image.delete()

            # Save new avatar
            profile.profile_image = request.FILES['avatar']
            profile.save()

            messages.success(request, 'Profile picture updated successfully!')
        except Exception as e:
            messages.error(request, f'Error updating profile picture: {str(e)}')

    return redirect('profile')


# Optional: Add these utility views if needed for AJAX functionality
@login_required
def get_profile_data(request):
    """
    Return user profile data as JSON for AJAX requests.
    """
    user = request.user
    profile = user.profile

    data = {
        'first_name': user.first_name,
        'last_name': user.last_name,
        'email': user.email,
        'phone': profile.phone,
        'bio': profile.bio,
        'timezone': profile.timezone,
        'language': profile.language,
        'email_notifications': profile.email_notifications,
        'push_notifications': profile.push_notifications,
    }

    return JsonResponse(data)







# Analytics Views



def analytics_dashboard(request):
    if not request.user.is_authenticated:
        raise PermissionDenied("Please login to access this page.")

    if not request.user:
        raise PermissionDenied("You don't have permission to access analytics.")

    try:
        # Get date range from request
        start_date = request.GET.get('start_date')
        end_date = request.GET.get('end_date')

        # Base queryset
        observations = SHEObservation.objects.all()

        # Apply date filtering if dates are provided
        if start_date and end_date:
            observations = observations.filter(
                date__range=[start_date, end_date]
            )

        # Get all counts with date filter applied
        open_count = observations.filter(status='Open').count()
        closed_count = observations.filter(status='Closed').count()

        # Get department data with date filter
        department_data = list(observations.values('department')
                             .annotate(count=Count('id'))
                             .order_by('department'))

        # Get priority distribution with date filter
        priority_data = list(observations.values('priority')
                           .annotate(count=Count('id'))
                           .order_by('priority'))

        # Get detailed observations for each priority with date filter
        detailed_observations = {}
        priorities = observations.values_list('priority', flat=True).distinct()

        for priority in priorities:
            observations_list = list(observations.filter(priority=priority).values(
                'id',
                'nature_of_issue',
                'department',
                'status',
                'created_at',
                'priority',
                'area',
                'location_details'
            ).order_by('-created_at'))

            if observations_list:
                detailed_observations[priority] = observations_list

        # Get detailed observations for each department with date filter
        department_observations = {}
        departments = observations.values_list('department', flat=True).distinct()

        for department in departments:
            dept_observations = list(observations.filter(department=department).values(
                'id',
                'nature_of_issue',
                'department',
                'status',
                'created_at',
                'priority',
                'area',
                'location_details'
            ).order_by('-created_at'))

            if dept_observations:
                department_observations[department] = dept_observations

        context = {
            'observations_by_department': json.dumps(department_data, cls=DjangoJSONEncoder),
            'observations_by_status': observations.values('status')
                                    .annotate(count=Count('id')),
            'observations_by_priority': json.dumps(priority_data, cls=DjangoJSONEncoder),
            'detailed_observations': json.dumps(detailed_observations, cls=DjangoJSONEncoder),
            'department_observations': json.dumps(department_observations, cls=DjangoJSONEncoder),
            'open_count': open_count,
            'closed_count': closed_count,
            'recent_observations': observations.order_by('-date')[:10],
            'total_observations': observations.count(),
            'pending_observations': observations.filter(status='pending').count(),
            'high_priority_count': observations.filter(priority='high').count(),
            'resolved_count': observations.filter(status='closed').count(),
            'unsafe_condition_count': observations.filter(issue_type='unsafe_condition').count(),
            'near_miss_count': observations.filter(issue_type='near_miss').count(),
            'bbs_count': observations.filter(issue_type='bbs').count(),
            # Add date range to context
            'start_date': start_date,
            'end_date': end_date,
        }

        return render(request, 'analytics/analytics.html', context)

    except Exception as e:
        print(f"Error in analytics_dashboard: {str(e)}")
        raise


# Feedback Views
class FeedbackCreateView(LoginRequiredMixin, CreateView):
    model = Feedback
    form_class = FeedbackForm
    template_name = 'feedback/create.html'
    success_url = reverse_lazy('dashboard')

    def form_valid(self, form):
        form.instance.user = self.request.user
        response = super().form_valid(form)
        messages.success(self.request, 'Thank you for your feedback!')
        return response


# API Endpoints for AJAX calls
# 
def get_observation_stats(request):
    stats = {
        'total': SHEObservation.objects.count(),
        'pending': SHEObservation.objects.filter(status='pending').count(),
        'in_progress': SHEObservation.objects.filter(status='in_progress').count(),
        'closed': SHEObservation.objects.filter(status='closed').count()
    }
    return JsonResponse(stats)


@require_POST
# 
def upload_attachment(request, observation_id):
    observation = get_object_or_404(SHEObservation, pk=observation_id)
    if not (request.user.is_manager_or_above or observation.reporter == request.user):
        return HttpResponseForbidden()

    files = request.FILES.getlist('attachments')
    for file in files:
        ObservationAttachment.objects.create(
            observation=observation,
            file=file
        )

    return JsonResponse({
        'status': 'success',
        'message': f'{len(files)} files uploaded successfully'
    })

# 
def password_reset(request):
    # Implement password reset logic here
    return render(request, 'registration/reset-password.html')

class TrackingListView(LoginRequiredMixin, ListView):
    model = ObservationActionTracking
    template_name = 'tracking/actionTracking.html'
    context_object_name = 'tracking_entries'

def tracking_list(request):
    entries = ObservationActionTracking.objects.all()
    return render(request, 'tracking/actionTrackingList.html', {'entries': entries})

# 
def tracking_detail(request, pk):
    entry = get_object_or_404(ObservationActionTracking, pk=pk)
    return render(request, 'tracking/detail.html', {'entry': entry})

# 
def tracking_create(request, observation_id=None):
    observation = None
    if observation_id:
        observation = get_object_or_404(SHEObservation, id=observation_id)

    if request.method == 'POST':
        form = ObservationActionTrackingForm(request.POST)
        if form.is_valid():
            entry = form.save(commit=False)
            if observation:
                entry.she_observation = observation
            entry.save()
            messages.success(request, 'Tracking entry created successfully.')
            return redirect('tracking_list')
    else:
        initial = {}
        if observation:
            initial = {
                'she_observation': observation,
                'action': observation.corrective_action,
                'priority_level': observation.priority
            }
        form = ObservationActionTrackingForm(initial=initial)

    return render(request, 'tracking/actionTracking.html', {
        'form': form,
        'observation': observation
    })


def tracking_create_general(request):
    if request.method == 'POST':
        form = ObservationActionTrackingForm(request.POST)
        if form.is_valid():
            entry = form.save()
            messages.success(request, 'Tracking entry created successfully.')
            return redirect('tracking_list')
    else:
        form = ObservationActionTrackingForm()

    return render(request, 'tracking/actionTracking.html', {'form': form})

# 
def tracking_update(request, pk):
    entry = get_object_or_404(ObservationActionTracking, pk=pk)

    if request.method == 'POST':
        form = ObservationActionTrackingForm(request.POST, instance=entry)
        if form.is_valid():
            tracking = form.save(commit=False)

            # Update completion date if status changed to completed
            if tracking.status == 'completed' and not tracking.completion_date:
                tracking.completion_date = timezone.now().date()
                if tracking.date:
                    tracking.time_to_completion = timezone.now().date() - tracking.date

            # Let the model's save method handle status updates
            tracking.save()

            messages.success(request, 'Tracking entry updated successfully.')
            return redirect('tracking_list')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = ObservationActionTrackingForm(instance=entry)

    return render(request, 'tracking/updateActionTracking.html', {
        'form': form,
        'entry': entry
    })

# 
def tracking_delete(request, pk):
    entry = get_object_or_404(ObservationActionTracking, pk=pk)
    if request.method == 'POST':
        entry.delete()
        messages.success(request, 'Tracking entry deleted successfully.')
        return redirect('tracking_list')
    return render(request, 'tracking/delete.html', {'entry': entry})

# 
def update_overdue_entries(request):
    updated = ObservationActionTracking.objects.update_overdue()
    messages.success(request, f'{updated} entries marked as overdue.')
    return redirect('tracking_list')

# 
def get_corrective_action(request, she_observation_id):
    observation = get_object_or_404(SHEObservation, pk=she_observation_id)
    return JsonResponse({
        'corrective_action': observation.corrective_action
    })
()
def dashboard(request):
    context = {
        'total_observations': SHEObservation.objects.count(),
        'pending_observations': SHEObservation.objects.filter(status='pending').count(),
        'high_priority_count': SHEObservation.objects.filter(priority='high').count(),
        'resolved_count': SHEObservation.objects.filter(status='closed').count(),
        'recent_observations': SHEObservation.objects.order_by('-date')[:10],
        'unsafe_condition_count': SHEObservation.objects.filter(issue_type='unsafe_condition').count(),
        'near_miss_count': SHEObservation.objects.filter(issue_type='near_miss').count(),
        'bbs_count': SHEObservation.objects.filter(issue_type='bbs').count(),
        # Add other necessary context data
    }
    return render(request, 'dashboard/index.html', context)


logger = logging.getLogger(__name__)


class CustomPasswordResetView(PasswordResetView):
    template_name = 'registration/password_reset_form.html'
    email_template_name = 'registration/password_reset_email.html'
    subject_template_name = 'registration/password_reset_subject.txt'
    success_url = reverse_lazy('password_reset_done')

    def form_valid(self, form):
        logger.info(f"Password reset initiated for email: {form.cleaned_data['email']}")
        return super().form_valid(form)


class CustomPasswordResetDoneView(PasswordResetDoneView):
    template_name = 'registration/password_reset_done.html'


class CustomPasswordResetConfirmView(PasswordResetConfirmView):
    template_name = 'registration/password_reset_confirm.html'
    success_url = reverse_lazy('password_reset_complete')

    def form_valid(self, form):
        logger.info("Password reset confirmation successful")
        return super().form_valid(form)


class CustomPasswordResetCompleteView(PasswordResetCompleteView):
    template_name = 'registration/password_reset_complete.html'

@login_required
def logout_view(request):
    logout(request)
    return redirect('login')