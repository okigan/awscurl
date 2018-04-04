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
                  'uri': 'https://awscurl-sample-bucket.s3.amazonaws.com/awscurl-sample-file:.txt?a=b',
                  'headers': headers,
                  'data': '',
                  'profile': '',
                  'access_key': 'AKIAIJTITPLWS3VWYTUA',
                  'secret_key': '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',
                  'security_token': None}

        make_request(**params)


        pass
