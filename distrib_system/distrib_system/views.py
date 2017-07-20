from django.http import HttpResponseRedirect

def autoredirect(request):
    return HttpResponseRedirect('/accounts/login/')
