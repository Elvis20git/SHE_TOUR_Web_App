# In your users/forms.py file

from django import forms
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.contrib.auth import get_user_model
import random
import string

from django.utils import timezone

from SHE.models import Feedback, SHEObservation, ObservationActionTracking


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

    class Meta:
        model = get_user_model()
        fields = ['username', 'password', 'remember_me']




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
    role = forms.ChoiceField(choices=[('user', 'User'), ('manager', 'Manager'), ('administrator', 'Administrator')],
                             widget=forms.Select(attrs={'class': 'form-control input-shadow', 'id': 'exampleInputRole'}))
    password1 = forms.CharField(widget=forms.TextInput(
        attrs={'class': 'form-control input-shadow', 'placeholder': 'Generated Password', 'id': 'exampleInputPassword', 'readonly': 'readonly'}
    ))
    password2 = forms.CharField(widget=forms.TextInput(
        attrs={'class': 'form-control input-shadow', 'placeholder': 'Confirm Password', 'id': 'exampleInputConfirmPassword', 'readonly': 'readonly'}
    ))
    account_activation = forms.BooleanField(required=False, widget=forms.CheckboxInput(
        attrs={'class': 'icheck-material-white', 'id': 'user-activation-checkbox'}
    ))

    class Meta:
        model = get_user_model()
        fields = ['first_name', 'last_name', 'username', 'email', 'department', 'role', 'password1', 'password2', 'account_activation']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        random_password = self.generate_random_password()
        self.random_password = random_password  # Store the generated password
        self.fields['password1'].initial = random_password
        self.fields['password2'].initial = random_password

    def generate_random_password(self):
        # Generate a random password
        characters = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choice(characters) for i in range(12))

    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data['email']
        user.first_name = self.cleaned_data['first_name']
        user.last_name = self.cleaned_data['last_name']
        if commit:
            user.save()
        return user


class FeedbackForm(forms.ModelForm):
    class Meta:
        model = Feedback
        fields = ['content']
        widgets = {
            'content': forms.Textarea(attrs={'rows': 4}),
        }


class SHEObservationForm(forms.ModelForm):
    class Meta:
        model = SHEObservation
        fields = ['department', 'date', 'time', 'area', 'nature_of_issue', 'issue_type', 'corrective_action', 'priority']
        widgets = {
            # 'reporter': forms.Textarea(attrs={'class': 'form-control', 'placeholder': 'reporter', 'id': 'exampleInputReporter'}),
            'department': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter Department'}),
            'date': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'time': forms.TimeInput(attrs={'class': 'form-control', 'type': 'time'}),
            'area': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter Area'}),
            'nature_of_issue': forms.Textarea(attrs={'class': 'form-control', 'placeholder': 'Describe the nature of the issue'}),
            'issue_type': forms.Select(attrs={'class': 'form-control'}),
            'corrective_action': forms.Textarea(attrs={'class': 'form-control', 'placeholder': 'Describe the corrective action'}),
            'priority': forms.Select(attrs={'class': 'form-control'}),

        }

    # terms_agreement = forms.BooleanField(required=True, widget=forms.CheckboxInput(attrs={'class': 'icheck-material-white'}))





class ObservationActionTrackingForm(forms.ModelForm):
    class Meta:
        model = ObservationActionTracking
        fields = ['date', 'she_observation', 'action', 'assign_to', 'deadline', 'status']
        widgets = {
            'date': forms.DateInput(attrs={'type': 'date', 'class': 'form-control'}),
            'she_observation': forms.Select(attrs={'class': 'form-control'}),
            'action': forms.Select(attrs={'class': 'form-control'}),
            'assign_to': forms.Select(attrs={'class': 'form-control'}),
            'deadline': forms.DateInput(attrs={'type': 'date', 'class': 'form-control'}),
            'status': forms.Select(attrs={'class': 'form-control'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['she_observation'].queryset = SHEObservation.objects.all().order_by('nature_of_issue')
        self.fields['action'].queryset = SHEObservation.objects.none()  # Initially empty
        self.fields['assign_to'].queryset = self.fields['assign_to'].queryset.order_by('username')

        if 'she_observation' in self.data:
            try:
                she_observation_id = int(self.data.get('she_observation'))
                self.fields['action'].queryset = SHEObservation.objects.filter(id=she_observation_id).values_list('corrective_action', flat=True)
            except (ValueError, TypeError):
                pass
        elif self.instance.pk:
            self.fields['action'].queryset = SHEObservation.objects.filter(id=self.instance.she_observation_id).values_list('corrective_action', flat=True)