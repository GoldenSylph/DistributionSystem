from django.db import models
from django.contrib.auth.models import User


class Student(models.Model):
    user = models.OneToOneField(User, primary_key=True)
    group = models.CharField(max_length=10, blank=True)
    course = models.CharField(max_length=20, blank=True)

    def __str__(self):
        return self.user.__str__()


class Cooperator(models.Model):
    user = models.OneToOneField(User, primary_key=True)
    work = models.CharField(max_length=100, blank=True)

    def __str__(self):
        return self.user.__str__()


class Professor(models.Model):
    user = models.OneToOneField(User, primary_key=True)
    education_course = models.CharField(max_length=100, blank=True)

    def __str__(self):
        return self.user.__str__()


class ScientificDirector(models.Model):
    user = models.OneToOneField(User, primary_key=True)
    education_course = models.CharField(max_length=100, blank=True)

    def __str__(self):
        return self.user.__str__()
