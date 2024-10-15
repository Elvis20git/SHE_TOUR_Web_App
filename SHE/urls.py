from django.urls import path

from . import views
from .views import CustomLoginView, CustomUserRegistrationView, SHEObservationCreateView

urlpatterns = [
    # path('', user_login, name='user_login'),  # Using user_login directly
    path('', CustomLoginView.as_view(), name='login'),
    path('register/', CustomUserRegistrationView.as_view(), name='register'),
    path('observation/', SHEObservationCreateView.as_view(), name='observation'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('password_reset/', views.password_reset, name='password_reset'),


    path('tracking/', views.tracking_list, name='tracking_list'),
    path('tracking/<int:pk>/', views.tracking_detail, name='tracking_detail'),
    path('tracking/create/', views.tracking_create, name='tracking_create'),
    path('tracking/<int:pk>/update/', views.tracking_update, name='tracking_update'),
    path('tracking/<int:pk>/delete/', views.tracking_delete, name='tracking_delete'),
    path('tracking/update-overdue/', views.update_overdue_entries, name='update_overdue_entries'),
    path('get-corrective-action/<int:she_observation_id>/', views.get_corrective_action, name='get_corrective_action'),
]

