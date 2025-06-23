from django.urls import path
from .views import *

urlpatterns = [
    path('signup/', SignupAPIView.as_view(), name='signup'),
    path('login/', LoginAPIView.as_view(), name='api-login'),
    path('user/', UserPageView.as_view(), name='user-api'),
    path('admin/', AdminPageView.as_view(), name='admin-api'),
    path('superadmin/', SuperAdminPageView.as_view(), name='superadmin-api'),
    path('logout/', LogoutAPIView.as_view(), name='api-logout'),
]
