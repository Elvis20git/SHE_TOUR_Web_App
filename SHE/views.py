from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordResetForm
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.paginator import Paginator
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.views import LoginView
from .forms import CustomLoginForm, CustomUserRegistrationForm, FeedbackForm, SHEObservationForm, \
    ObservationActionTrackingForm
from django.views.generic import CreateView
from django.urls import reverse_lazy
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.views.generic import ListView, DetailView, CreateView, UpdateView, DeleteView
from .models import AuditTrail, Feedback, SHEObservation, ObservationActionTracking
from django.http import JsonResponse
import sweetify


class CustomLoginView(LoginView):
    form_class = CustomLoginForm
    template_name = 'SHE/login.html'

    def get_success_url(self):
        return reverse_lazy('dashboard')

    def form_valid(self, form):
        remember_me = form.cleaned_data.get('remember_me')
        if not remember_me:
            self.request.session.set_expiry(0)
        self.request.session.modified = True

        # Perform the login
        super(CustomLoginView, self).form_valid(form)

        # Check if request is AJAX
        if self.request.headers.get('x-requested-with') == 'XMLHttpRequest':
            return JsonResponse({
                'success': True,
                'redirect_url': self.get_success_url()
            })
        return super().form_valid(form)

    def form_invalid(self, form):
        # Check if request is AJAX
        if self.request.headers.get('x-requested-with') == 'XMLHttpRequest':
            return JsonResponse({
                'success': False
            })
        return super().form_invalid(form)

class CustomUserRegistrationView(CreateView):
    form_class = CustomUserRegistrationForm
    template_name = 'SHE/register.html'  # Make sure this matches your template file name
    success_url = reverse_lazy('login')  # Redirect to login page after successful registration

    def form_valid(self, form):
        # You can add any additional logic here before saving the user
        return super().form_valid(form)



# Dashboard
def dashboard(request):

    return render(request, 'SHE/index.html')


class SHEObservationListView(LoginRequiredMixin, ListView):
    model = SHEObservation
    template_name = 'she_observation_list.html'
    context_object_name = 'observations'
    paginate_by = 10

    def get_queryset(self):
        return SHEObservation.objects.filter(reporter=self.request.user)

class SHEObservationDetailView(LoginRequiredMixin, DetailView):
    model = SHEObservation
    template_name = 'she_observation_detail.html'
    context_object_name = 'observation'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['audit_trail'] = AuditTrail.objects.filter(observation=self.object)
        return context

    def form_valid(self, form):
        form.instance.reporter = self.request.user
        response = super().form_valid(form)
        AuditTrail.objects.create(user=self.request.user, action='Created', observation=self.object)
        messages.success(self.request, 'Observation created successfully.')
        return response

class SHEObservationUpdateView(LoginRequiredMixin, UserPassesTestMixin, UpdateView):
    model = SHEObservation
    form_class = SHEObservationForm
    template_name = 'she_observation_form.html'
    success_url = reverse_lazy('she_observation_list')

    def test_func(self):
        obj = self.get_object()
        return obj.reporter == self.request.user or self.request.user.is_staff

    def form_valid(self, form):
        response = super().form_valid(form)
        AuditTrail.objects.create(user=self.request.user, action='Updated', observation=self.object)
        messages.success(self.request, 'Observation updated successfully.')
        return response

class SHEObservationDeleteView(LoginRequiredMixin, UserPassesTestMixin, DeleteView):
    model = SHEObservation
    template_name = 'she_observation_confirm_delete.html'
    success_url = reverse_lazy('she_observation_list')

    def test_func(self):
        obj = self.get_object()
        return obj.reporter == self.request.user or self.request.user.is_staff

    def delete(self, request, *args, **kwargs):
        messages.success(self.request, 'Observation deleted successfully.')
        return super().delete(request, *args, **kwargs)

class FeedbackCreateView(LoginRequiredMixin, CreateView):
    model = Feedback
    form_class = FeedbackForm
    template_name = 'feedback_form.html'
    success_url = reverse_lazy('feedback_success')

    def form_valid(self, form):
        form.instance.user = self.request.user
        return super().form_valid(form)

class AuditTrailListView(LoginRequiredMixin, UserPassesTestMixin, ListView):
    model = AuditTrail
    template_name = 'audit_trail_list.html'
    context_object_name = 'audit_trails'
    paginate_by = 20

    def test_func(self):
        return self.request.user.is_staff

    def get_queryset(self):
        observation_id = self.kwargs.get('observation_id')
        return AuditTrail.objects.filter(observation_id=observation_id).order_by('-timestamp')

class SHEObservationCreateView(LoginRequiredMixin, CreateView):
        model = SHEObservation
        form_class = SHEObservationForm
        template_name = 'SHE/forms.html'
        success_url = reverse_lazy('dashboard')

        def form_valid(self, form):
            form.instance.reporter = self.request.user
            form.instance.status = 'pending'  # Set default status
            response = super().form_valid(form)
            AuditTrail.objects.create(user=self.request.user, action='Created', observation=self.object)
            messages.success(self.request, 'Observation created successfully.')
            return response


def password_reset(request):

   password_reset_form = PasswordResetForm()

   if request.method == 'POST':
       password_reset_form = PasswordResetForm(data=request.POST)
       if password_reset_form.is_valid():
           password_reset_form.save()
           messages.success()




#Action Tracking

@login_required
def tracking_list(request):
    tracking_list = ObservationActionTracking.objects.all()
    paginator = Paginator(tracking_list, 10)  # Show 10 entries per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    return render(request, 'tracking_list.html', {'page_obj': page_obj})

@login_required
def tracking_detail(request, pk):
    tracking = get_object_or_404(ObservationActionTracking, pk=pk)
    return render(request, 'tracking_detail.html', {'tracking': tracking})

@login_required
def tracking_create(request):
    if request.method == 'POST':
        form = ObservationActionTrackingForm(request.POST)
        if form.is_valid():
            tracking = form.save()
            messages.success(request, 'Tracking entry created successfully.')
            return redirect('dashboard')
    else:
        form = ObservationActionTrackingForm()
    SHE = SHEObservation.objects.all()
    context = {
        'form': form,
        'SHE' : SHE,
    }
    return render(request, 'SHE/actionForm.html', context)

@login_required
def tracking_update(request, pk):
    tracking = get_object_or_404(ObservationActionTracking, pk=pk)
    if request.method == 'POST':
        form = ObservationActionTrackingForm(request.POST, instance=tracking)
        if form.is_valid():
            tracking = form.save()
            messages.success(request, 'Tracking entry updated successfully.')
            return redirect('tracking_detail', pk=tracking.pk)
    else:
        form = ObservationActionTrackingForm(instance=tracking)
    return render(request, 'tracking_form.html', {'form': form, 'tracking': tracking})

@login_required
def tracking_delete(request, pk):
    tracking = get_object_or_404(ObservationActionTracking, pk=pk)
    if request.method == 'POST':
        tracking.delete()
        messages.success(request, 'Tracking entry deleted successfully.')
        return redirect('tracking_list')
    return render(request, 'tracking_confirm_delete.html', {'tracking': tracking})

@login_required
def update_overdue_entries(request):
    updated_count = ObservationActionTracking.update_all_overdue()
    messages.success(request, f'{updated_count} overdue entries updated successfully.')
    return redirect('tracking_list')


def get_corrective_action(request, she_observation_id):
    try:
        she_observation = SHEObservation.objects.get(id=she_observation_id)
        return JsonResponse({'corrective_action': she_observation.corrective_action})
    except SHEObservation.DoesNotExist:
        return JsonResponse({'error': 'SHE Observation not found'}, status=404)


