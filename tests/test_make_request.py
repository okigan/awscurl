#!/usr/bin/env python

import datetime
from unittest import TestCase

from mock import patch

from awscurl.awscurl import make_request

__author__ = 'iokulist'


def my_mock_get():
    class Object():
        pass

    def ss(*args, **kargs):
        print("in mock")
        response = Object()
        response.status_code = 200
        response.text = 'some text'
        return response

    return ss


def my_mock_send_request():
    class Object():
        pass

    def ss(*args, **kargs):
        print("in mock")
        response = Object()
        response.status_code = 200
        response.text = 'some text'
        return response

    return ss


def my_mock_utcnow():
    class Object():
        pass

    def ss(*args, **kargs):
        print("in mock")
        return datetime.datetime.utcfromtimestamp(0)

    return ss


class TestMakeRequest(TestCase):
    maxDiff = None
    @patch('requests.get', new_callable=my_mock_get)
    @patch('awscurl.awscurl.send_request', new_callable=my_mock_send_request)
    @patch('awscurl.awscurl.now', new_callable=my_mock_utcnow)
    def test_make_request(self, *args, **kvargs):
        headers = {}
        params = {'method': 'GET',
                  'service': 'ec2',
                  'region': 'region',
                  'uri': 'https://user:pass@host:123/path/?a=b&c=d',
                  'headers': headers,
                  'data': '',
                  'profile': '',
                  'access_key': '',
                  'secret_key': '',
                  'security_token': ''}
        make_request(**params)

        expected = {'x-amz-date': '19700101T000000Z',
                    'Authorization': 'AWS4-HMAC-SHA256 Credential=/19700101/region/ec2/aws4_request, SignedHeaders=host;x-amz-date, Signature=de2b9ea384c10b03314afa10532adac358f8c93e3f3dd5bd724eda24a367a7ef',
                    'x-amz-content-sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
		    'x-amz-security-token': ''}

        self.assertEqual(expected, headers)

        pass

class TestMakeRequestWithToken(TestCase):
    maxDiff = None
    @patch('requests.get', new_callable=my_mock_get)
    @patch('awscurl.awscurl.send_request', new_callable=my_mock_send_request)
    @patch('awscurl.awscurl.now', new_callable=my_mock_utcnow)
    def test_make_request(self, *args, **kvargs):
        headers = {}
        params = {'method': 'GET',
                  'service': 'ec2',
                  'region': 'region',
                  'uri': 'https://user:pass@host:123/path/?a=b&c=d',
                  'headers': headers,
                  'data': '',
                  'profile': '',
                  'access_key': 'ABC',
                  'secret_key': 'DEF',
                  'security_token': 'GHI'}
        make_request(**params)

        expected = {'x-amz-date': '19700101T000000Z',
		    'x-amz-content-sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                    'Authorization': 'AWS4-HMAC-SHA256 Credential=ABC/19700101/region/ec2/aws4_request, SignedHeaders=host;x-amz-date;x-amz-security-token, Signature=e767448ca06e8f3a17548d4193ea29afa759b84f957a71d0a051815f5ebfedfa',
                    'x-amz-security-token': 'GHI'}

        self.assertEqual(expected, headers)

        pass
