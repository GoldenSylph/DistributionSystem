from django.db import IntegrityError
from django.shortcuts import render
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.http import HttpResponseRedirect
from django.contrib.auth.decorators import login_required
from django.http import Http404

from .utils import *

# Create your views here.


def register(request):
    if request.method == "POST":
        user = User(username=request.POST['username'])
        user.set_password(request.POST['password'])
        user.first_name = request.POST['first_name']
        user.last_name = request.POST['last_name']
        user.email = request.POST['email']
        try:
            user.save()
        except IntegrityError:
            messages.add_message(request, messages.INFO, 'Этот логин занят')
            return render(request, 'login.html')
        positions = request.POST.getlist('position')
        initialize_user(user, positions)
        user = authenticate(username=request.POST['username'], password=request.POST['password'])
        if user is not None:
            if user.is_active:
                login(request, user)
                messages.add_message(request, messages.INFO, 'Incorrect')
                return HttpResponseRedirect('/accounts/my_profile/' + str(user.id))
            else:
                messages.add_message(request, messages.INFO, 'Your account is not active')
    return render(request, 'register.html')


def new_login(request):
    if request.POST:
        username = request.POST.get('login')
        password = request.POST.get('password')
        return auth(request, username, password, messages)
    else:
        return render(request, 'login.html')


def new_logout(request):
    
    logout(request)
    return HttpResponseRedirect('/accounts/login/')
                

@login_required(login_url='/accounts/login')
def base_context(request):
    user = request.user
    is_student = get_entity_from_db(user, 'Student')
    is_cooperator = get_entity_from_db(user, 'Cooperator')
    is_professor = get_entity_from_db(user, 'Professor')
    is_sci_director = get_entity_from_db(user, 'ScientificDirector')
    context = {
        "user_id": user.id,
        "user_surname": user.last_name,
        "user_name": user.first_name,
        "user_email": user.email,
        "user_username": user.username,
        "is_student": is_student,
        "is_professor": is_professor,
        "is_cooperator": is_cooperator,
        "is_sci_director": is_sci_director
    }
    return context


@login_required(login_url='/accounts/login')
def my_profile(request, user_id):
    return render(request, "accounts/parts/my_data.html", base_context(request))


@login_required(login_url='/accounts/login')
def edit_profile(request, user_id):
    user = request.user
    if request.POST["user_new_name"] is not "":
        user.first_name = request.POST["user_new_name"]
    if request.POST["user_new_surname"] is not "":
        user.last_name = request.POST["user_new_surname"]
    if request.POST["user_new_username"] is not "":
        user.username = request.POST["user_new_username"]
    if request.POST["user_new_email"] is not "":
        user.email = request.POST["user_new_email"]
    user.save()

    student, cooperator, professor, sci_director = get_all_entities_from_db(user)

    if student is not None:
        if request.POST["user_stud_new_group"] is not "":
            student.group = request.POST["user_stud_new_group"]
        if request.POST["user_stud_new_course"] is not "":
            student.course = request.POST["user_stud_new_course"]
        student.save()

    if cooperator is not None:
        if request.POST["user_coop_new_work"] is not "":
            cooperator.work = request.POST["user_coop_new_work"]
        cooperator.save()

    if professor is not None:
        if request.POST["user_prof_new_education_course"] is not "":
            professor.education_course = request.POST["user_prof_new_education_course"]
        professor.save()

    if sci_director is not None:
        if request.POST["user_sci_dir_new_education_course"] is not "":
            sci_director.education_course = request.POST["user_sci_dir_new_education_course"]
        sci_director.save()

    return my_profile(request, user_id)


@login_required(login_url='/accounts/login')
def edit_password(request, user_id):    
    user = request.user
    newpass = request.POST["user_new_pass"]
    confnewpass = request.POST["user_new_pass_confirm"]
    if newpass is not "" and confnewpass is not "":
        if str(newpass) == str(confnewpass):
            user.set_password(newpass)
            user.save()
            messages.add_message(request, messages.INFO, 'Пароль изменен!')
        else:
            messages.add_message(request, messages.INFO, 'Пароли не совпадают!')
    return auth(request, user.username, str(newpass), messages)
