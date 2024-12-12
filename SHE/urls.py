from django.contrib.auth.views import LogoutView
from django.urls import path
from . import views
from .views import (
    CustomLoginView,
    CustomUserRegistrationView,
    ObservationListView,
    ObservationDetailView,
    SHEObservationCreateView,
    ObservationUpdateView,
    # Corrected imports to match your views.py class names
    ActionTrackingCreateView,
    ActionTrackingUpdateView,
    NotificationPreferenceUpdateView,
    FeedbackCreateView, TrackingListView, ObservationDeleteView,
    CustomPasswordResetView,
    CustomPasswordResetDoneView,
    CustomPasswordResetConfirmView,
    CustomPasswordResetCompleteView, logout_view
)
from django.contrib.auth.decorators import user_passes_test

def is_manager_or_above(user):
    return user.is_authenticated and user.is_manager_or_above

urlpatterns = [
    # Authentication URLs
    path('', CustomLoginView.as_view(), name='login'),
    path('register/', CustomUserRegistrationView.as_view(), name='register'),
    path('logout/', logout_view, name='logout'),

    # Dashboard
    path('dashboard/', views.dashboard, name='dashboard'),
    # path('analytics/', views.analytics_dashboard, name='analytics_dashboard'),
    path('analytics/',
             user_passes_test(is_manager_or_above, login_url='login')(views.analytics_dashboard),
             name='analytics_dashboard'),
    # path('get-chart-data/', views.get_chart_data, name='get_chart_data'),

    # SHE Observation URLs
    path('observations/', ObservationListView.as_view(), name='observation_list'),
    path('observations/<int:pk>/', ObservationDetailView.as_view(), name='observation_detail'),
    path('observations/create/', SHEObservationCreateView.as_view(), name='observation_create'),
    path('observations/<int:pk>/update/', ObservationUpdateView.as_view(), name='observation_update'),
    path('update-observation-status/<int:observation_id>/', views.update_observation_status, name='update_observation_status'),
    path('observation/<int:pk>/delete/', ObservationDeleteView.as_view(), name='observation_delete'),
    path('attachment/delete/', views.delete_attachment, name='delete_attachment'),
    path('user-search/', views.user_search, name='user_search'),
    # path('observation/<int:observation_id>/tag-member/', views.tag_member, name='tag_member'),
    # path('observation/<int:observation_id>/untag-member/', views.untag_member, name='untag_member'),
    path('observations/<int:observation_id>/manage-tags/',
     views.manage_group_members_tags,
     name='manage_group_members_tags'),

    # Action Tracking URLs
    # Action Tracking URLs - Fix the order
    path('tracking/create/<int:observation_id>/', views.tracking_create, name='tracking_create'),  # Specific observation tracking
    path('tracking/create/', views.tracking_create_general, name='tracking_create_general'),  # General tracking
    path('tracking/<int:pk>/', views.tracking_detail, name='tracking_detail'),
    path('tracking/', views.tracking_list, name='tracking_list'),
    path('tracking/<int:pk>/update/', views.tracking_update, name='tracking_update'),
    path('tracking/<int:pk>/delete/', views.tracking_delete, name='tracking_delete'),

    # Notification URLs
    path('notifications/', views.notification_list, name='notification_list'),
    # path('notifications/<int:pk>/mark-read/', views.mark_notification_read, name='mark_notification_read'),
    path('notification-preferences/', NotificationPreferenceUpdateView.as_view(), name='notification_preferences'),
    path('notifications/mark-read/', views.mark_notification_read, name='mark_notification_read'),
    path('notifications/mark-all-read/', views.mark_all_notifications_read, name='mark_all_notifications_read'),
    path('notifications/unread-count/', views.get_unread_count, name='get_unread_count'),


    # Profile
    path('profile/', views.profile_view, name='profile'),
    path('profile/update/', views.update_profile, name='update_profile'),
    path('profile/settings/', views.update_settings, name='update_settings'),
    path('profile/password/', views.change_password, name='change_password'),
    path('profile/avatar/', views.update_avatar, name='update_avatar'),



    path('password_reset/',
            CustomPasswordResetView.as_view(),
            name='password_reset'),
        path('password_reset/done/',
            CustomPasswordResetDoneView.as_view(),
            name='password_reset_done'),
        path('reset/<uidb64>/<token>/',
            CustomPasswordResetConfirmView.as_view(),
            name='password_reset_confirm'),
        path('reset/done/',
            CustomPasswordResetCompleteView.as_view(),
            name='password_reset_complete'),
    # Feedback URL
    path('feedback/', FeedbackCreateView.as_view(), name='feedback_create'),

    # API Endpoints
    path('api/observation-stats/', views.get_observation_stats, name='get_observation_stats'),
    path('api/upload-attachment/<int:observation_id>/', views.upload_attachment, name='upload_attachment'),
    path('api/corrective-action/<int:she_observation_id>/', views.get_corrective_action, name='get_corrective_action'),
]