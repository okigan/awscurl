#!/usr/bin/env python
# -*- coding: utf-8 -*-

import base64
import io
import socket
import tempfile

from unittest import TestCase, mock
from contextlib import redirect_stderr

import sys
import os

import requests

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

    def test_exit_code_without_fail_option(self, *args, **kwargs):
        self.assertEqual(
            inner_main(['--verbose', '--service', 's3', 'https://awscurl-sample-bucket.s3.amazonaws.com']),
            0
        )

    def test_exit_code_with_fail_option(self, *args, **kwargs):
        self.assertEqual(
            inner_main(['--verbose', '--fail-with-body', '--service', 's3', 'https://awscurl-sample-bucket.s3.amazonaws.com']),
            22
        )

class TestInnerMainMethodEmptyCredentials(TestCase):
    maxDiff = None

    def test_exit_code_without_fail_option(self, *args, **kwargs):
        self.assertEqual(
            inner_main(['--verbose', '--access_key', '', '--secret_key', '', '--session_token', '', '--service', 's3',
                        'https://awscurl-sample-bucket.s3.amazonaws.com']),
            0
        )

    def test_exit_code_with_fail_option(self, *args, **kwargs):
        self.assertEqual(
            inner_main(['--verbose', '--fail-with-body', '--access_key', '', '--secret_key', '', '--session_token', '', '--service', 's3',
                        'https://awscurl-sample-bucket.s3.amazonaws.com']),
            22
        )


class TestVerboseOutputRedaction(TestCase):
    """Verbose output must never contain credential values (AGENTS.md: never log AWS credentials).

    Regression test for the -v credential leak: the args dump in inner_main and the
    header dump in __send_request both carried full secrets.
    """
    maxDiff = None

    def test_verbose_output_masks_credentials(self):
        access_key = 'AKIAIOSFODNN7EXAMPLE'
        secret_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'

        # Bind (but never listen on) a local port so the request fails fast with
        # ConnectionError after both verbose log sites have run - no live network needed
        probe = socket.socket()
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
        uri = 'https://127.0.0.1:{0}/awscurl-sample-file'.format(port)

        stderr = io.StringIO()
        try:
            with redirect_stderr(stderr):
                with self.assertRaises(requests.exceptions.ConnectionError):
                    inner_main(['--verbose', '--access_key', access_key, '--secret_key', secret_key,
                                '--service', 's3', uri])
        finally:
            probe.close()

        output = stderr.getvalue()
        # no credential value may appear anywhere in verbose output
        self.assertNotIn(access_key, output)
        self.assertNotIn(secret_key, output)
        # the Authorization header is masked wholesale ('Credential=' only appears
        # in a leaked Authorization value)
        self.assertNotIn('Credential=', output)
        # masking happened, and the useful debugging output is intact
        self.assertIn('***', output)
        self.assertIn('host', output)
        self.assertIn('x-amz-date', output)
