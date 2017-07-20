from django.contrib import admin
from .models import Container, Laboratory, Course, Practice, ScienceHead, Request, StudentToLabStorage
# Register your models here.

admin.site.register(Laboratory)
admin.site.register(Course)
admin.site.register(Practice)
admin.site.register(ScienceHead)
admin.site.register(Request)
admin.site.register(StudentToLabStorage)