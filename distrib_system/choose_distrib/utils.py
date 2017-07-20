'''
Created on 13 июл. 2017 г.

@author: Андрей Романов

'''
# -*- coding: utf-8 -*-
import importlib

from .models import Request, StudentToLabStorage


modulename, dot, classname = 'choose_distrib.models.classname'.rpartition('.')
module = importlib.import_module(modulename)


class Triple:
    def __init__(self, first_item, second_item, third_item):
        self.first_item = first_item
        self.second_item = second_item
        self.third_item = third_item


def get_container_with_number_of_occupied_from_db(user, container_type):
    containers = list(getattr(module, container_type).objects.all())
    list_of_triples = []
    for container in containers:
        count = StudentToLabStorage.objects.filter(container=container).distinct().count()
        request_status = list(Request.objects.filter(container=container, student=user).order_by('send_date'))
        status = None
        if request_status:
            status = request_status.pop().status
        triple = Triple(container, count, status)
        list_of_triples.append(triple)

    return list_of_triples


# Автор следующих четырех функций: Андрей
def get_containers_from_db(user, container_class):
    containers = getattr(module, container_class).objects.all()
    return list(containers)


def get_requests_for_student(user, request_type):
    requests = list(Request.objects.filter(request_type=request_type, student=user))
    return requests
