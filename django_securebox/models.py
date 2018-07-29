import pickle

import nacl.encoding
import nacl.hash
import nacl.public
import nacl.pwhash
import nacl.secret
from django.contrib.auth import get_user_model
from django.db import models
from nacl.pwhash import argon2id as chosen_kdf

from django_securebox.utils import SecureBoxException


class SecureObject(models.Model):
    data = models.BinaryField()

    @classmethod
    def clean_orphaned(cls):
        cls.objects.filter(links=None).delete()

    def get_data(self, object_key):
        try:
            data = nacl.secret.SecretBox(
                object_key
            ).decrypt(
                bytes(self.data)
            )

            return pickle.loads(data)

        except nacl.exceptions.CryptoError as e:
            self.delete()
            raise SecureBoxException('Internal CryptoError') from e

    def set_data(self, object_key, value):
        data = pickle.dumps(value)
        self.data = nacl.secret.SecretBox(
            object_key
        ).encrypt(
            data
        )
        self.save()
        self.refresh_from_db()


class SecureObjectLink(models.Model):
    user = models.ForeignKey(
        to=get_user_model(),
        on_delete=models.CASCADE,
        related_name='secure_objects',
    )
    obj = models.ForeignKey(
        'SecureObject',
        on_delete=models.CASCADE,
        related_name='links',
    )
    name = models.CharField(max_length=255)
    object_key = models.BinaryField()

    class Meta:
        unique_together = (
            ('user', 'name'),
        )

    def get_data(self, key):
        try:
            object_key = nacl.secret.SecretBox(
                key
            ).decrypt(
                bytes(self.object_key),
            )

            return self.obj.get_data(object_key)

        except (SecureBoxException, nacl.exceptions.CryptoError) as e:
            self.delete()
            SecureObject.clean_orphaned()
            raise SecureBoxException('Internal CryptoError') from e

    def set_data(self, key, value):
        object_key = None
        if self.object_key:
            with suppress(nacl.exceptions.CryptoError):  # Ignore error, set a new object_key
                object_key = nacl.secret.SecretBox(
                    key
                ).decrypt(
                    bytes(self.object_key),
                )

        if not object_key:
            object_key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)

            self.object_key = nacl.secret.SecretBox(
                key
            ).encrypt(
                object_key
            )

        self.obj.set_data(object_key, value)
        self.obj = self.obj
        self.save()
        self.refresh_from_db()


class UserSecureBox(models.Model):
    user = models.OneToOneField(
        to=get_user_model(),
        on_delete=models.CASCADE,
        related_name='secure_box',
    )
    _user_key = models.BinaryField(db_column='user_key')

    @property
    def user_key(self):
        if hasattr(self, '_user_key_wrapkey'):
            try:
                return nacl.secret.SecretBox(self._user_key_wrapkey).decrypt(
                    bytes(self._user_key)
                )
            except nacl.exceptions.CryptoError:
                self.reset_user_key()
                return self.user_key
        else:
            raise SecureBoxException('Need to login() for user_key operations')

    @user_key.setter
    def user_key(self, value):
        if hasattr(self, '_user_key_wrapkey'):
            self._user_key = nacl.secret.SecretBox(self._user_key_wrapkey).encrypt(
                value
            )
        else:
            raise SecureBoxException('Need to login() for user_key operations')

    def generate_keys(self):
        if not self._user_key:
            self.reset_user_key()

    def reset_user_key(self):
        # Delete user_key, delete private_key
        # Delete all dependent SecureObjectLink
        # Clean orphaned SecureObject
        # Create and store new user_key
        #  new private_key, public_key

        self._user_key = b''
        self.save()

        self.user.secure_objects.filter().delete()
        SecureObject.clean_orphaned()

        self.user_key = nacl.utils.random(32)
        self.save()

    def login(self, pwd):
        self._user_key_wrapkey = chosen_kdf.kdf(
            nacl.secret.SecretBox.KEY_SIZE,
            pwd.encode('UTF-8'),
            nacl.hash.blake2b(
                data=self.user.password.encode('US-ASCII'),
                digest_size=chosen_kdf.SALTBYTES,
                encoder=nacl.encoding.RawEncoder),
            opslimit=nacl.pwhash.OPSLIMIT_SENSITIVE,
            memlimit=nacl.pwhash.MEMLIMIT_MODERATE,
        )
        if not self._user_key:
            self.generate_keys()
