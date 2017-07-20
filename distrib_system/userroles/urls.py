from django.conf.urls import url
from . import views

app_name = 'userroles'
urlpatterns = [
    url(r'^register/$', views.register, name='register'),
    url(r'^login/$', views.new_login, name='login'),
    url(r'^logout/$', views.new_logout, name='logout'),
    url(r'^my_profile/(?P<user_id>[0-9]+)/$', views.my_profile, name='profile'),
    url(r'^my_profile/(?P<user_id>[0-9]+)/editprof/$', views.edit_profile, name='edit_profile'),
    url(r'^my_profile/(?P<user_id>[0-9]+)/editpass/$', views.edit_password, name='edit_password'),
]