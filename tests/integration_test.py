#!/usr/bin/env python

import base64

from unittest import TestCase

from mock import patch

from awscurl.awscurl import make_request

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
                  'binary_payload': False}

        r = make_request(**params)

        self.assertEqual(r.status_code, 200)
