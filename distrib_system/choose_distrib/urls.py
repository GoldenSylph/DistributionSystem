from django.conf.urls import include, url
from . import views

app_name = 'choose_distrib'
urlpatterns = [
    url(r'^my_profile/(?P<user_id>[0-9]+)/', 
    include([
        url(r'^student/', 
        include([
            url(r'^(?P<container_type>[A-z]+)/(?P<request_type>[A-z]+)/(?P<container_id>[0-9]+)/$', views.student_make_request, name='student_make_request'), 
            url(r'^(?P<container_type>[A-z]+)/$', views.student_form, name='student')])),                                          
        url(r'^professor/', 
        include([
            url(r'^(?P<request_type>[A-z]+)/(?P<container_id>[0-9]+)/(?P<user_id2>[0-9]+)/(?P<request_status>[1-2])/$', views.professor_request_change_status, name='professor_request_change_status'),
            url(r'^(?P<request_type>[A-z]+)/(?P<action_type>[A-z]+)$', views.professor_form, name='professor')])),
        url(r'^sc_dir/', 
        include([ 
            url(r'^(?P<request_type>[A-z]+)/(?P<container_id>[0-9]+)/(?P<user_id2>[0-9]+)/(?P<request_status>[1-2])/$', views.sc_dir_request_change_status, name='sc_dir_request_change_status')])),
            url(r'^(?P<request_type>[A-z]+)/(?P<action_type>[A-z]+)$', views.sci_dir_form, name='sc_dir_sci_dir'),
        url(r'^cooperator/', 
        include([
            url(r'^(?P<request_type>[A-z]+)/(?P<action_type>[A-z]+)$', views.coop_form, name='cooperator')]))
        ]))]
