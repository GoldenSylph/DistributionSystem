from django import forms
from django.contrib.auth.models import User


class UserForm(forms.ModelForm):
    POSITIONS = (
        ('student', 'Студент'),
        ('professor', 'Преподаватель'),
        ('cooperator', 'Сотрудник'),
        ('scientific_director', 'Научный руководитель'),
    )
    username = forms.CharField(max_length=50, label="Имя пользователя")
    last_name = forms.CharField(max_length=50, required=True, label="Фамилия")
    first_name = forms.CharField(max_length=50, required=True, label="Имя")
    position = forms.MultipleChoiceField(required=True, choices=POSITIONS, widget=forms.CheckboxSelectMultiple())
    email = forms.EmailField(widget=forms.EmailInput, label="Электронная почта")
    password = forms.CharField(widget=forms.PasswordInput, label="Пароль")
    pass2 = forms.CharField(widget=forms.PasswordInput, label="Повторите пароль")

    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'first_name', 'last_name']
