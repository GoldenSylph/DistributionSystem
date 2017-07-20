from django.contrib.auth.models import User
from django.shortcuts import render

from .models import Request, Container
from .utils import *
from django.contrib import messages
from userroles.views import base_context
    

# Create your views here.
'''
    Короче, сюда лезть только готовыми к дикой боли и дебаггингу))
'''
'''
    STUDENTS HERE
'''


# Авторы : Андрей, Даниил, Роман
def student_form(request, user_id, container_type):
    user = request.user
    list_of_triples = get_container_with_number_of_occupied_from_db(user, container_type)
    context = {
        'user_id': user_id,
        'triples': list_of_triples,
    }
    context.update(base_context(request))
    return render(request, 'accounts/parts/container_table.html', context)


def student_make_request(request, user_id, container_type, request_type, container_id):
    user = request.user
    container = Container.objects.get(id=container_id)
    context = {
        'user_id': user_id,
    }
    context.update(base_context(request))
    if Request.objects.filter(request_type=request_type, student=user).exclude(status=2):
        return render(request, 'accounts/parts/request_already_exist.html', context)

    student_request = Request()
    student_request.student = user
    student_request.container = container
    student_request.status = 0
    student_request.request_type = request_type
    student_request.save()

    return student_form(request, user_id, container_type)

'''
PROFESSORS HERE
'''


def professor_form(request, user_id, request_type, action_type):
    user = request.user
    context = {}
    containers = list(Container.objects.filter(container_director=user))
    requests = []
    try:
        for container in containers:
            requests.append(list(Request.objects.filter(request_type=request_type, container=container).order_by('send_date')))
        context = {
            'user_id': user_id,
            "requests": requests,
        }
    except:
        messages.add_message(request, messages.INFO, 'Список заявок пуст')
    context.update(base_context(request))
    if action_type == 'view_requests':
        return render(request, 'accounts/parts/requests_table_with_buttons.html', context)
    if action_type == 'print_requests':
        return render(request, 'accounts/parts/print_template.html', context)


def professor_request_change_status(request, user_id, request_type, container_id, user_id2, request_status):
    student = User.objects.get(id=user_id2)
    container = Container.objects.get(id=container_id)
    student_request = Request.objects.get(student=student, request_type=request_type, container=container)
    student_request.status = request_status
    student_request.save()
    action_type = 'view_requests'
    storage_object = StudentToLabStorage()
    storage_object.student = student
    storage_object.container = container
    storage_object.save()
    return professor_form(request, user_id, request_type, action_type)

'''
SCIENCE DIR HERE
'''


def sci_dir_form(request, user_id, request_type, action_type):
    user = request.user
    containers = Container.objects.filter(container_director=user)
    requests = []
    context = {}
    try:
        for container in containers:
            requests.append(list(Request.objects.filter(request_type=request_type, container=container).order_by('send_date')))
            context = {
                'user_id': user_id,
                "requests": requests,
            }
    except:
        messages.add_message(request, messages.INFO, 'Список заявок пуст')
    context.update(base_context(request))
    if action_type == 'view_requests':
        return render(request, 'accounts/parts/requests_table_with_buttons.html', context)
    if action_type == 'print_requests':
        return render(request, 'accounts/parts/print_template.html', context)


def sc_dir_request_change_status(request, user_id, request_type, container_id, user_id2, request_status):
    student = User.objects.get(id=user_id2)
    container = Container.objects.get(id=container_id)
    student_request = Request.objects.get(student=student, request_type=request_type, container=container)
    student_request.status = request_status
    student_request.save()
    action_type = 'view_requests'
    storage_object = StudentToLabStorage()
    storage_object.student = student
    storage_object.container = container
    storage_object.save()
    return sci_dir_form(request, user_id, request_type, action_type)

'''
COOPERATORS HERE
'''


def coop_form(request, user_id, request_type, action_type):
    context = {}
    requests = []
    try:
        requests.append(list(Request.objects.filter(request_type=request_type)))
        context = {
            'user_id': user_id,
            "requests": requests,
        }
    except:
        messages.add_message(request, messages.INFO, 'Список заявок пуст')
    context.update(base_context(request))
    if action_type == 'view_requests':
        return render(request, 'accounts/parts/requests_table_without_buttons.html', context)
    if action_type == 'print_requests':
        return render(request, 'accounts/parts/print_template.html', context)
