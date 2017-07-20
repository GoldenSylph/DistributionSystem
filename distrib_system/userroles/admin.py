from django.contrib import admin
from .models import Student, Professor, Cooperator, ScientificDirector

# Register your models here.

admin.site.register(Student)
admin.site.register(Professor)
admin.site.register(Cooperator)
admin.site.register(ScientificDirector)
