from pprint import pformat

import django
import pytest
from django.conf import settings
from django.conf.urls import url
from django.contrib.auth import get_user_model
from django.http import HttpResponse
from django.shortcuts import reverse


@pytest.fixture
def login_user():
    def do_login(client, user):
        return client.post(reverse('login'), {'username': user.username, 'password': 'test_password'})
    return do_login

@pytest.fixture
def user():
    user = get_user_model().objects.create(username='regular_user', is_staff=True)
    user.set_password('test_password')
    user.save()
    yield user
    user.delete()

def test_view(request):
    response = "Test\n" + pformat(list(request.securebox.items()))
    return HttpResponse(response, content_type='text/plain')

def lazy_loginview(*args, **kwargs):  ## FIXME Is there a more elegant way to do this?
    from django.contrib.auth.views import LoginView
    v = LoginView.as_view()
    return v(*args, **kwargs)

urlpatterns = (
    url('^login$', lazy_loginview, name='login'),
    url('^test$', test_view, name='test'),
)

def pytest_configure():
    settings.configure(
        DEBUG=True,
        USE_TZ=True,
        DATABASES={
            'default': {
                'ENGINE': 'django.db.backends.sqlite3',
                'NAME': 'django_securebox.db',
            }
        },
        INSTALLED_APPS=[
            'django.contrib.auth',
            'django.contrib.sessions',
            'django.contrib.contenttypes',
            'django.contrib.staticfiles',
            'django_securebox',
        ],
        MIDDLEWARE = [
            'django.middleware.security.SecurityMiddleware',
            'django.contrib.sessions.middleware.SessionMiddleware',
            'django_securebox.middleware.SecureBoxMiddleware',
            'django.middleware.common.CommonMiddleware',
            'django.middleware.csrf.CsrfViewMiddleware',
            'django.contrib.auth.middleware.AuthenticationMiddleware',
        ],
        PASSWORD_HASHERS=(
            'django.contrib.auth.hashers.MD5PasswordHasher',
        ),
        AUTH_USER_MODEL='auth.User',
        ROOT_URLCONF=urlpatterns,
    )
