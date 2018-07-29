from django.utils.deprecation import MiddlewareMixin
from django.utils.functional import SimpleLazyObject

from django_securebox.utils import SecureBox


def get_securebox(request):
    if not hasattr(request, '_cached_securebox'):
        request._cached_securebox = SecureBox(request)
    return request._cached_securebox

class SecureBoxMiddleware(MiddlewareMixin):
    def process_request(self, request):
        assert hasattr(request, 'session'), (
              "The SecureBox middleware requires session middleware "
              "to be installed. Edit your MIDDLEWARE%s setting to insert "
              "'django.contrib.sessions.middleware.SessionMiddleware' before "
              "'django_securebox.middleware.SecureBoxMiddleware'."
        ) % ("_CLASSES" if settings.MIDDLEWARE is None else "")
    
        request.securebox = SimpleLazyObject(lambda: get_securebox(request))

    def process_response(self, request, response):
        if hasattr(request, '_cached_securebox'):
            request._cached_securebox.process_response(response)
        return response
