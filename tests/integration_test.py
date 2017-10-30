#!/usr/bin/env python

import datetime
import logging

from unittest import TestCase

from mock import patch

from awscurl.awscurl import make_request

__author__ = 'iokulist'


class TestMakeRequestWithToken(TestCase):
    maxDiff = None

    def test_make_request(self, *args, **kvargs):
        headers = {}
        params = {'method': 'GET',
                  'service': 's3',
                  'region': 'us-east-1',
                  'uri': 'https://awscurl-sample-bucket.s3.amazonaws.com?a=b',
                  'headers': headers,
                  'data': '',
                  'profile': '',
                  'access_key': 'AKIAIKDYYMAAECYXKVZQ',
                  'secret_key': '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',
                  'security_token': None}

        make_request(**params)


        pass
