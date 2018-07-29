from django.contrib.auth import user_logged_in, user_logged_out
from django.dispatch import receiver

from .middleware import get_securebox


@receiver(user_logged_in)
def login_securebox(sender, signal, request, user, **kwargs):
    if 'password' in request.POST:
        get_securebox(request).login(request.POST['password'])

@receiver(user_logged_out)
def logout_securebox(sender, signal, request, user, **kwargs):
    get_securebox(request).logout()
