from django.db import models
from django.core.validators import MaxValueValidator, MinValueValidator
from django.contrib.auth.models import User


'''
@author: Роман Багаутдинов
'''

# Create your models here.


class Container(models.Model):
    # Абстрактный контейнер. НЕ СОЗДАВАТЬ ОБЪЕКТЫ, ТОЛЬКО НАСЛЕДНИКИ
    container_name = models.CharField(max_length=100, verbose_name='Название')
    container_director = models.ManyToManyField(User)
    container_capacity = models.IntegerField(
        default=0,
        validators=[MaxValueValidator(300), MinValueValidator(0)]
    )
    CONTAINERCHOISE = (
        ('Laboratory', 'laboratory'),
        ('Course', 'course'),
        ('Practice', 'practice'),
        ('ScienceHead', 'science_director')
    )
    container_type = models.CharField(max_length=20, choices=CONTAINERCHOISE)

    def __str__(self):
        return self.container_name


class Laboratory(Container):

    def __str__(self):
        return "Название лаборатории: {0}".format(self.container_name)


class Course(Container):

    def __str__(self):
        return "Название курса: {0}".format(self.container_name)


class Practice(Container):

    def __str__(self):
        return "Название практики: {0}".format(self.container_name)


class ScienceHead(Container):

    def __str__(self):
        return "Научный руководитель: {0}".format(self.container_name)


class Request(models.Model):
    # Запрос в "контейнер"
    student = models.ForeignKey(User, on_delete=models.CASCADE)
    container = models.ForeignKey(Container, on_delete=models.CASCADE)

    STATUS = (
        (0, 'SENDED'),
        (1, 'ACCEPTED'),
        (2, 'DECLINED'),
    )
    status = models.IntegerField(
        default=0,
        validators=[MaxValueValidator(2), MinValueValidator(0)],
        choices=STATUS
    )
    REQUESTTYPE = (
        ('Laboratory', 'laboratory'),
        ('Course', 'course'),
        ('Practice', 'practice'),
        ('ScienceHead', 'science_director')
    )
    request_type = models.CharField(max_length=20, choices=REQUESTTYPE)

    send_date = models.DateTimeField(auto_now_add=True)
    change_date = models.DateField(auto_now=True)

    def __str__(self):
        return "{0} {1} - {2} :: {3}".format(self.student.first_name, self.student.last_name, self.container, self.send_date)


class StudentToLabStorage(models.Model):
    student = models.ForeignKey(User, on_delete=models.CASCADE)
    container = models.ForeignKey(Container, on_delete=models.CASCADE)

    def __str__(self):
        return "{0} {1} - {2}".format(self.student.first_name, self.student.last_name, self.container)
