#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for `django_securebox` package."""

import pytest
from django.shortcuts import reverse

ani = pytest.mark.xfail(reason='Anonymous user not implemented yet', strict=True)

@pytest.mark.django_db
@ani
def test_always_present(client):
    a = client.get(reverse('test'))
    assert a.wsgi_request.securebox

@pytest.mark.django_db
def test_login_works(login_user, client, user):
    login_response = login_user(client, user)
    assert login_response.cookies.get('django_securebox_cookie_key')
    
    simple_response = client.get(reverse('test'))
    assert simple_response.wsgi_request.securebox
    assert not simple_response.cookies.get('django_securebox_cookie_key')
