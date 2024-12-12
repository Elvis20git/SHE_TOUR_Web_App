# # SHE_TOUR/urls.py
# from django.contrib import admin
# from django.urls import path, include
#
# urlpatterns = [
#     # path('registration/', include('django.contrib.auth.urls')),  # Django auth URLs
#     path('admin/', admin.site.urls),
#     path('', include('SHE.urls')),  # Your app URLs
# ]

from django.contrib import admin
from django.urls import path, include
from django.contrib.auth import views as auth_views
from django.conf.urls.static import static
from django.conf import settings
urlpatterns = [
    path('admin/', admin.site.urls),
    # Add these login/logout URLs
    path('registration/login/', auth_views.LoginView.as_view(), name='login'),
    path('registration/logout/', auth_views.LogoutView.as_view(), name='logout'),
    # Include your app's URLs
    path('', include('SHE.urls')),  # Replace your_app_name with your actual app name
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)