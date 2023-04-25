#!/usr/bin/env python
# -*- coding: utf-8 -*-

import base64

from unittest import TestCase

import sys
import os

# this block resolves issues with pytest/tox, overall project dir structure
# should be updated, some hints at can be found here: 
# https://stackoverflow.com/questions/55737714/how-does-a-tox-environment-set-its-sys-path
print(f'sys.path={sys.path}')
this_script_dir=os.path.dirname(os.path.abspath(__file__))
extra_path=os.path.join(this_script_dir, '..', 'awscurl')
if not os.path.exists(extra_path):
    print(f'extra_path does not exist: {extra_path}')
sys.path.append(extra_path)
print(f'sys.path2={sys.path}')

from awscurl.awscurl import make_request, inner_main  # nopep8: E402


__author__ = 'iokulist'


class TestMakeRequestWithToken(TestCase):
    maxDiff = None

    def test_make_request(self, *args, **kvargs):
        headers = {}
        access_key = base64.b64decode('QUtJQUkyNkxPQU5NSlpLNVNQWUE=').decode("utf-8")
        secret_key = base64.b64decode('ekVQbE9URjU0Mys5M0l6UlNnNEVCOEd4cjFQV2NVa1p0TERWSmY4ag==').decode("utf-8")
        params = {'method': 'GET',
                  'service': 's3',
                  'region': 'us-east-1',
                  'uri': 'https://awscurl-sample-bucket.s3.amazonaws.com/awscurl-sample-file:.txt?a=b',
                  'headers': headers,
                  'data': '',
                  'access_key': access_key,
                  'secret_key': secret_key,
                  'security_token': None,
                  'data_binary': False}

        r = make_request(**params)

        self.assertEqual(r.status_code, 200)


class TestMakeRequestWithTokenAndBinaryData(TestCase):
    maxDiff = None

    def test_make_request(self, *args, **kvargs):
        headers = {}
        access_key = base64.b64decode('QUtJQUkyNkxPQU5NSlpLNVNQWUE=').decode("utf-8")
        secret_key = base64.b64decode('ekVQbE9URjU0Mys5M0l6UlNnNEVCOEd4cjFQV2NVa1p0TERWSmY4ag==').decode("utf-8")
        params = {'method': 'GET',
                  'service': 's3',
                  'region': 'us-east-1',
                  'uri': 'https://awscurl-sample-bucket.s3.amazonaws.com/awscurl-sample-file:.txt?a=b',
                  'headers': headers,
                  'data': b'C\xcfI\x91\xc1\xd0\tw<\xa8\x13\x06{=\x9b\xb3\x1c\xfcl\xfe\xb9\xb18zS\xf4%i*Q\xc9v',
                  'access_key': access_key,
                  'secret_key': secret_key,
                  'security_token': None,
                  'data_binary': True}

        r = make_request(**params)

        self.assertEqual(r.status_code, 200)


class TestMakeRequestWithTokenAndEnglishData(TestCase):
    maxDiff = None

    def test_make_request(self, *args, **kvargs):
        headers = {}
        access_key = base64.b64decode('QUtJQUkyNkxPQU5NSlpLNVNQWUE=').decode("utf-8")
        secret_key = base64.b64decode('ekVQbE9URjU0Mys5M0l6UlNnNEVCOEd4cjFQV2NVa1p0TERWSmY4ag==').decode("utf-8")
        params = {'method': 'GET',
                  'service': 's3',
                  'region': 'us-east-1',
                  'uri': 'https://awscurl-sample-bucket.s3.amazonaws.com/awscurl-sample-file:.txt?a=b',
                  'headers': headers,
                  'data': 'Test',
                  'access_key': access_key,
                  'secret_key': secret_key,
                  'security_token': None,
                  'data_binary': False}

        r = make_request(**params)

        self.assertEqual(r.status_code, 200)


class TestMakeRequestWithTokenAndNonEnglishData(TestCase):
    maxDiff = None

    def test_make_request(self, *args, **kvargs):
        headers = {}
        access_key = base64.b64decode('QUtJQUkyNkxPQU5NSlpLNVNQWUE=').decode("utf-8")
        secret_key = base64.b64decode('ekVQbE9URjU0Mys5M0l6UlNnNEVCOEd4cjFQV2NVa1p0TERWSmY4ag==').decode("utf-8")
        params = {'method': 'GET',
                  'service': 's3',
                  'region': 'us-east-1',
                  'uri': 'https://awscurl-sample-bucket.s3.amazonaws.com/awscurl-sample-file:.txt?a=b',
                  'headers': headers,
                  'data': u'テスト',
                  'access_key': access_key,
                  'secret_key': secret_key,
                  'security_token': None,
                  'data_binary': False}

        r = make_request(**params)

        self.assertEqual(r.status_code, 200)


class TestInnerMainMethod(TestCase):
    maxDiff = None

    def test_exit_code(self, *args, **kwargs):
        self.assertEqual(
            inner_main(['--verbose', '--service', 's3', 'https://awscurl-sample-bucket.s3.amazonaws.com']),
            1
        )
