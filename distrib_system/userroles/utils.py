'''
Created on 12 июл. 2017 г.

@author: Андрей Романов

'''
# -*- coding: utf-8 -*-

from django.contrib.auth.models import Group, User
from .models import Student, Cooperator, Professor, ScientificDirector
import importlib
from django.http import HttpResponseRedirect
from django.http import Http404
from django.contrib.auth import authenticate, login
from django.shortcuts import render

modulename, dot, classname = 'userroles.models.classname'.rpartition('.')
module = importlib.import_module(modulename)

# Возвращает ассоц. массив
def get_entity_from_db(user, name):
    model = None
    try :
        model=getattr(module, name).objects.get(user=user)
        if model is not None:
            return model
    except:
        return None

def get_all_entities_from_db(user):
    is_student = get_entity_from_db(user, 'Student')
    is_cooperator = get_entity_from_db(user, 'Cooperator')
    is_professor = get_entity_from_db(user, 'Professor')
    is_sci_director = get_entity_from_db(user, 'ScientificDirector')
    return (is_student, is_cooperator, is_professor, is_sci_director)

def initialize_user(user, positions):
    for p in positions:
        model = getattr(module, p)(user=user)
        model.save()

def auth(request, username, password, messages):
    user = authenticate(username=username, password=password)
    if user is not None:
        if user.is_active:
            login(request, user)
            return HttpResponseRedirect('/accounts/my_profile/' + str(user.id))
        else:
            raise Http404
    else:
        messages.add_message(request, messages.INFO, 'Неправильный логин или пароль')
        messages.get_messages(request)
        return render(request, 'login.html')