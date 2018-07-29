import pickle
from contextlib import suppress
from enum import Enum

import nacl
from django.conf import settings
from django.utils.functional import SimpleLazyObject


def session_binary_get(request, key):
    return nacl.encoding.Base64Encoder.decode(request.session[key])

def session_binary_set(request, key, value):
    request.session[key] = nacl.encoding.Base64Encoder.encode(value).decode('us-ascii')

COOKIE_KEY = 'django_securebox_cookie_key'
SALT_KEY = '_django_securebox_salt'
USER_KEY = '_django_securebox_user_key'
TRANSIENT_KEY = '_django_securebox_transient_keys'
COOKIE_KEY_SIZE = 32

class Storage(Enum):
    TRANSIENT_ONLY = 'session'
    PERMANENT_ONLY = 'db'
    PERMANENT_OR_TRANSIENT = 'db,session'
    TRANSIENT_OR_PERMANENT = 'session,db'
    ALL= 'all'

# TODO Tests: No session; session, then login; session, login, session, logout, session
#  login, then database clear
#  login then password change
#  login then external password change
#  two sessions
#  two sessions, password change in one
#  two sessions, login one, then logout
#  name in transient storage and same name in permanent storage
#  Store permanent without user
#  Deletion

class SecureBox:
    def __init__(self, request):
        self.request = request
        self.set_cookies = {}
        self.delete_cookies = set()

        from .models import UserSecureBox
        self.userbox = SimpleLazyObject(lambda: UserSecureBox.objects.get_or_create(user=self.request.user)[0])

    def login(self, password):
        self.userbox.login(password)
        self.user_key = self.userbox.user_key

    def logout(self):
        self.delete_cookies.add(COOKIE_KEY)
        if SALT_KEY in self.request.session:
            del self.request.session[SALT_KEY]
        if USER_KEY in self.request.session:
            del self.request.session[USER_KEY]

    def process_response(self, response):
        for key, value in self.set_cookies.items():
            ## FIXME Sane params
            response.set_cookie(key, value, max_age=5*365*24*60*60, httponly=True)

        for key in self.delete_cookies:
            response.delete_cookie(key)


    def get_session_key(self, *prefixes):
        data_items = [
            item.encode('utf-8')
            for item in prefixes + (
                self.request.user.password,
                settings.SECRET_KEY,
            )
        ]

        # FIXME: Include user_key  (dependent on user being logged in)

        data_items.append(self.cookie_key)

        input_data = b"".join( ("|{:04X}|".format(len(item)).encode('utf-8') + item) for item in data_items)

        return nacl.hash.blake2b(
            input_data,
            key=self.session_salt,
            encoder=nacl.encoding.RawEncoder,
            digest_size=nacl.secret.SecretBox.KEY_SIZE,
        )

    @property
    def session_salt(self):
        if not SALT_KEY in self.request.session:
            session_binary_set(self.request, SALT_KEY, nacl.utils.random(16))
        return session_binary_get(self.request, SALT_KEY)

    @property
    def cookie_key(self):
        if not hasattr(self, '_cookie_key'):
            if not COOKIE_KEY in self.request.COOKIES:
                self.cookie_key = nacl.utils.random(COOKIE_KEY_SIZE)
            else:
                self._cookie_key = nacl.encoding.Base64Encoder.decode(
                    self.request.COOKIES[COOKIE_KEY]
                )
        return self._cookie_key

    @cookie_key.setter
    def cookie_key(self, value):
        self._cookie_key = value
        self.set_cookies[COOKIE_KEY] = nacl.encoding.Base64Encoder.encode(value).decode('us-ascii')
    

    @property
    def user_key(self):
        if not hasattr(self, '_user_key'):
            self._user_key = nacl.secret.SecretBox(
                self.get_session_key('user_key')
            ).decrypt(
                session_binary_get(self.request, USER_KEY)
            )

        return self._user_key

    @user_key.setter
    def user_key(self, value):
        session_binary_set(self.request, USER_KEY, 
            nacl.secret.SecretBox(
                self.get_session_key('user_key')
            ).encrypt(
                value
            )
        )
        self._user_key = value

    def __setitem__(self, key, value):
        self.store_value(key, value, storage=Storage.TRANSIENT_OR_PERMANENT)

    def __getitem__(self, key):
        return self.fetch_value(key, storage=Storage.TRANSIENT_OR_PERMANENT)

    def __delitem__(self, key):  # TODO Check semantics
        self.delete_value(key, storage=Storage.TRANSIENT_OR_PERMANENT)

    def __contains__(self, key):
        return self.has_key(key)

    def has_key(self, key, storage=Storage.TRANSIENT_OR_PERMANENT):
        try:
            self.fetch_value(key, storage=storage)
            return True
        except KeyError:
            return False

    def __iter__(self):
        return self.keys()

    def keys(self):
        return list(
            set(
                key for key in self.request.session.get(TRANSIENT_KEY, [])
                if self.has_key(key)
            ).union(set(
                link_obj.name for link_obj in self.userbox.user.secure_objects.all()
                if self.has_key(link_obj.name)  # FIXME Optimize
            ))
        )

    def items(self):
        for name in self.keys():
            with suppress(KeyError):
                yield (name, self[name])  # FIXME Optimize

    def get(self, key, default=Ellipsis):
        return self.fetch_value(key, default=default)

    def fetch_value(self, key, storage=Storage.TRANSIENT_OR_PERMANENT, default=Ellipsis):
        if storage in (Storage.TRANSIENT_OR_PERMANENT, Storage.TRANSIENT_ONLY):
            with suppress(KeyError):
                return self._fetch_value_transient(key)

        if storage in (Storage.TRANSIENT_OR_PERMANENT, Storage.PERMANENT_ONLY, Storage.PERMANENT_OR_TRANSIENT):
            with suppress(KeyError):
                return self._fetch_value_permanent(key)

        if storage is Storage.PERMANENT_OR_TRANSIENT:
            with suppress(KeyError):
                return self._fetch_value_transient(key)

        if default is Ellipsis:
            raise KeyError
        else:
            return default

    def store_value(self, key, value, storage=Storage.PERMANENT_OR_TRANSIENT):
        if storage is Storage.TRANSIENT_OR_PERMANENT:
            if self._store_value_transient(key, value, update_only=True):
                return
            if self._store_value_permanent(key, value, update_only=True):
                return

        elif storage is Storage.PERMANENT_OR_TRANSIENT:
            if self._store_value_permanent(key, value, update_only=True):
                return
            if self._store_value_transient(key, value, update_only=True):
                return

        if storage in (Storage.TRANSIENT_OR_PERMANENT, Storage.TRANSIENT_ONLY):
            self._store_value_transient(key, value)

            if storage is Storage.TRANSIENT_ONLY:
                self.delete_value(key, storage=Storage.PERMANENT_ONLY)

        elif storage in (Storage.PERMANENT_OR_TRANSIENT, Storage.PERMANENT_ONLY):
            # TODO Test explicitly delete transient value
            self._store_value_permanent(key, value)

            if storage is Storage.PERMANENT_ONLY:
                self.delete_value(key, storage=Storage.TRANSIENT_ONLY)

    def _fetch_value_transient(self, key):
        if not key in self.request.session.get(TRANSIENT_KEY, []):
            raise KeyError
        data_key = self.get_session_key("session", key)
        with suppress(nacl.exceptions.CryptoError):
            return pickle.loads(nacl.secret.SecretBox(data_key).decrypt(session_binary_get(self.request, key)))
        raise KeyError

    def _store_value_transient(self, key, value, update_only=False):
        if update_only:
            try:
                self._fetch_value_transient(key)
            except KeyError:
                return False

        data_key = self.get_session_key("session", key)
        session_binary_set(self.request, key,
            nacl.secret.SecretBox(data_key).encrypt(pickle.dumps(value))
        )
        transient_list = self.request.session.get(TRANSIENT_KEY, [])
        if not key in transient_list:
            transient_list.append(key)
            self.request.session[TRANSIENT_KEY] = transient_list
        return True

    def _fetch_value_permanent(self, key):
        link_obj = self.userbox.user.secure_objects.filter(name=key).first()
        if link_obj:
            with suppress(SecureBoxException):  # Just fail silently and return KeyError if decryption fails
                return link_obj.get_data(self.user_key)
        raise KeyError

    def _store_value_permanent(self, key, value, update_only=False):
        link_obj = self.userbox.user.secure_objects.filter(name=key).first()

        try:
            link_key = self.user_key
        except KeyError:
            if update_only:
                return False
            else:
                raise

        if update_only:
            if link_obj:
                try:
                    link_obj.get_data(link_key)
                except SecureBoxException:
                    return False
            else:
                return False

        if not link_obj:
            from .models import SecureObject, SecureObjectLink

            obj = SecureObject()
            link_obj = SecureObjectLink(obj=obj, user=self.userbox.user, name=key)

        link_obj.set_data(link_key, value)
        return True

    def delete_value(self, key, storage=Storage.ALL):
        if storage in (Storage.PERMANENT_OR_TRANSIENT, Storage.PERMANENT_ONLY, Storage.ALL):
            link_obj = self.userbox.user.secure_objects.filter(name=key).first()
            if link_obj:
                link_obj.obj.delete()
                if storage is not Storage.ALL:
                    return

        if storage in (Storage.PERMANENT_OR_TRANSIENT, Storage.TRANSIENT_ONLY, Storage.TRANSIENT_OR_PERMANENT, Storage.ALL):
            if key in self.request.session.get(TRANSIENT_KEY, []):
                self.request.session[TRANSIENT_KEY].remove(key)
                del self.request.session[key]
                self.request.session.modified = True
                if storage is not Storage.ALL:
                    return

        if storage is Storage.TRANSIENT_OR_PERMANENT:
            link_obj = self.userbox.user.secure_objects.filter(name=key).first()
            if link_obj:
                link_obj.obj.delete()


class SecureBoxException(Exception):
    pass
