#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import datetime
import json
import sys

from unittest import TestCase

from mock import patch

from awscurl.awscurl import aws_url_encode, make_request

from requests.exceptions import SSLError
from requests import Response

import pytest
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


def my_mock_send_request_verify():
    class Object():
        pass

    def ss(uri, data, headers, method, verify, allow_redirects, **kargs):
        print("in mock")
        if not verify:
            raise SSLError
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
    @patch('awscurl.awscurl.__send_request', new_callable=my_mock_send_request)
    @patch('awscurl.awscurl.__now', new_callable=my_mock_utcnow)
    def test_make_request(self, *args, **kvargs):
        headers = {}
        params = {'method': 'GET',
                  'service': 'ec2',
                  'region': 'region',
                  'uri': 'https://user:pass@host:123/path/?a=b&c=d',
                  'headers': headers,
                  'data': '',
                  'access_key': '',
                  'secret_key': '',
                  'security_token': '',
                  'data_binary': False}
        make_request(**params)

        expected = {'x-amz-date': '19700101T000000Z',
                    'Authorization': 'AWS4-HMAC-SHA256 Credential=/19700101/region/ec2/aws4_request, SignedHeaders=host;x-amz-date, Signature=de2b9ea384c10b03314afa10532adac358f8c93e3f3dd5bd724eda24a367a7ef',
                    'x-amz-content-sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                    'x-amz-security-token': ''}

        self.assertEqual(expected, headers)

        pass

    @patch('requests.get', new_callable=my_mock_get)
    @patch('awscurl.awscurl.__send_request', new_callable=my_mock_send_request)
    @patch('awscurl.awscurl.__now', new_callable=my_mock_utcnow)
    def test_make_request2(self, *args, **kvargs):

        payload = json.dumps({
            "key": "<redacted0>",
            })
        creds = {
            "access_key": "<redacted1>",
            "secret_key": "<redacted2>",
            "token": "<redacted3>"
        }

        headers = {
                "Content-Type": "application/json; charset:UTF-8",
                "Connection": "keep-alive",
                "Content-Encoding": "amz-1.0",
                "x-amz-requestsupertrace": "true"
            }
        
        params = {
            'method':'POST',
            'service':'service-<redacted>',
            'region':"region-<redacted>",
            'uri':"<redacted>",
            'headers': headers,
            'data':payload,
            'data_binary':False,
            'access_key':creds['access_key'],
            'secret_key':creds['secret_key'],
            'security_token':creds['token'],
        }
        
        make_request(**params)

        expected = {
            "Content-Type": "application/json; charset:UTF-8",
            "Connection": "keep-alive",
            "Content-Encoding": "amz-1.0",
            "x-amz-requestsupertrace": "true",
            "Authorization": "AWS4-HMAC-SHA256 Credential=<redacted1>/19700101/region-<redacted>/service-<redacted>/aws4_request, SignedHeaders=host;x-amz-date;x-amz-requestsupertrace;x-amz-security-token, Signature=77e0f17c91f179231fcdf42f4387539b935117600de340ab1904f66302c181d7",
            "x-amz-date": "19700101T000000Z",
            "x-amz-content-sha256": "4930e13bdc55bb30accf137260ec8fa65b35658360e92a5f8498def3f8ab6144",
            "x-amz-security-token": "<redacted3>"
            }

        self.assertEqual(expected, headers)

        pass


class TestMakeRequestVerifySSLRaises(TestCase):
    maxDiff = None

    @patch('awscurl.awscurl.__send_request', new_callable=my_mock_send_request_verify)
    @patch('awscurl.awscurl.__now', new_callable=my_mock_utcnow)
    def test_make_request(self, *args, **kvargs):
        headers = {}
        params = {'method': 'GET',
                  'service': 'ec2',
                  'region': 'region',
                  'uri': 'https://user:pass@host:123/path/?a=b&c=d',
                  'headers': headers,
                  'data': '',
                  'access_key': '',
                  'secret_key': '',
                  'security_token': '',
                  'data_binary': False,
                  'verify': False,
                  'allow_redirects': False}

        with pytest.raises(SSLError):
            make_request(**params)

        pass


class TestMakeRequestVerifySSLPass(TestCase):
    maxDiff = None

    @patch('awscurl.awscurl.__send_request', new_callable=my_mock_send_request_verify)
    @patch('awscurl.awscurl.__now', new_callable=my_mock_utcnow)
    def test_make_request(self, *args, **kvargs):
        headers = {}
        params = {'method': 'GET',
                  'service': 'ec2',
                  'region': 'region',
                  'uri': 'https://user:pass@host:123/path/?a=b&c=d',
                  'headers': headers,
                  'data': '',
                  'access_key': '',
                  'secret_key': '',
                  'security_token': '',
                  'data_binary': False,
                  'verify': True,
                  'allow_redirects': False}
        make_request(**params)

        expected = {'x-amz-date': '19700101T000000Z',
                    'Authorization': 'AWS4-HMAC-SHA256 Credential=/19700101/region/ec2/aws4_request, SignedHeaders=host;x-amz-date, Signature=de2b9ea384c10b03314afa10532adac358f8c93e3f3dd5bd724eda24a367a7ef',
                    'x-amz-content-sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                    'x-amz-security-token': ''}

        self.assertEqual(expected, headers)

        pass


class TestMakeRequestWithBinaryData(TestCase):
    maxDiff = None

    @patch('requests.get', new_callable=my_mock_get)
    @patch('awscurl.awscurl.__send_request', new_callable=my_mock_send_request)
    @patch('awscurl.awscurl.__now', new_callable=my_mock_utcnow)
    def test_make_request(self, *args, **kvargs):
        headers = {}
        params = {'method': 'GET',
                  'service': 'ec2',
                  'region': 'region',
                  'uri': 'https://user:pass@host:123/path/?a=b&c=d',
                  'headers': headers,
                  'data': b'C\xcfI\x91\xc1\xd0\tw<\xa8\x13\x06{=\x9b\xb3\x1c\xfcl\xfe\xb9\xb18zS\xf4%i*Q\xc9v',
                  'access_key': '',
                  'secret_key': '',
                  'security_token': '',
                  'data_binary': True}
        make_request(**params)

        expected = {'x-amz-date': '19700101T000000Z',
                    'Authorization': 'AWS4-HMAC-SHA256 Credential=/19700101/region/ec2/aws4_request, SignedHeaders=host;x-amz-date, Signature=6ebcf316c9bb50bb7b2bbabf128dddde3babbf16badfd31ddc40838e7592d5df',
                    'x-amz-content-sha256': '3f514228bd64bbff67daaa80e482aee0e0b0c51891d3a64e4abfa145f4364b99',
                    'x-amz-security-token': ''}

        self.assertEqual(expected, headers)

        pass


class TestMakeRequestWithToken(TestCase):
    maxDiff = None

    @patch('requests.get', new_callable=my_mock_get)
    @patch('awscurl.awscurl.__send_request', new_callable=my_mock_send_request)
    @patch('awscurl.awscurl.__now', new_callable=my_mock_utcnow)
    def test_make_request(self, *args, **kvargs):
        headers = {}
        params = {'method': 'GET',
                  'service': 'ec2',
                  'region': 'region',
                  'uri': 'https://user:pass@host:123/path/?a=b&c=d',
                  'headers': headers,
                  'data': '',
                  'access_key': 'ABC',
                  'secret_key': 'DEF',
                  'security_token': 'GHI',
                  'data_binary': False}
        make_request(**params)

        expected = {'x-amz-date': '19700101T000000Z',
                    'x-amz-content-sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                    'Authorization': 'AWS4-HMAC-SHA256 Credential=ABC/19700101/region/ec2/aws4_request, SignedHeaders=host;x-amz-date;x-amz-security-token, Signature=e767448ca06e8f3a17548d4193ea29afa759b84f957a71d0a051815f5ebfedfa',
                    'x-amz-security-token': 'GHI'}

        self.assertEqual(expected, headers)

        pass


class TestMakeRequestWithTokenAndBinaryData(TestCase):
    maxDiff = None

    @patch('requests.get', new_callable=my_mock_get)
    @patch('awscurl.awscurl.__send_request', new_callable=my_mock_send_request)
    @patch('awscurl.awscurl.__now', new_callable=my_mock_utcnow)
    def test_make_request(self, *args, **kvargs):
        headers = {}
        params = {'method': 'GET',
                  'service': 'ec2',
                  'region': 'region',
                  'uri': 'https://user:pass@host:123/path/?a=b&c=d',
                  'headers': headers,
                  'data': b'C\xcfI\x91\xc1\xd0\tw<\xa8\x13\x06{=\x9b\xb3\x1c\xfcl\xfe\xb9\xb18zS\xf4%i*Q\xc9v',
                  'access_key': 'ABC',
                  'secret_key': 'DEF',
                  'security_token': 'GHI',
                  'data_binary': True}
        make_request(**params)

        expected = {'x-amz-date': '19700101T000000Z',
                    'x-amz-content-sha256': '3f514228bd64bbff67daaa80e482aee0e0b0c51891d3a64e4abfa145f4364b99',
                    'Authorization': 'AWS4-HMAC-SHA256 Credential=ABC/19700101/region/ec2/aws4_request, SignedHeaders=host;x-amz-date;x-amz-security-token, Signature=edcee42e10d5a4cec5414ebe938edcf292a9a33261809523e2df16281d452c5f',
                    'x-amz-security-token': 'GHI'}

        self.assertEqual(expected, headers)

        pass


class TestHostFromHeaderUsedInCanonicalHeader(TestCase):
    maxDiff = None

    @patch('requests.get', new_callable=my_mock_get)
    @patch('awscurl.awscurl.__send_request', new_callable=my_mock_send_request)
    @patch('awscurl.awscurl.__now', new_callable=my_mock_utcnow)
    def test_make_request(self, *args, **kvargs):
        headers = {'host': 'some.other.host.address.com'}
        params = {'method': 'GET',
                  'service': 'ec2',
                  'region': 'region',
                  'uri': 'https://user:pass@host:123/path/?a=b&c=d',
                  'headers': headers,
                  'data': '',
                  'access_key': 'ABC',
                  'secret_key': 'DEF',
                  'security_token': 'GHI',
                  'data_binary': False}
        make_request(**params)

        expected = {'host': 'some.other.host.address.com',
                    'x-amz-date': '19700101T000000Z',
                    'x-amz-content-sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                    'Authorization': 'AWS4-HMAC-SHA256 Credential=ABC/19700101/region/ec2/aws4_request, SignedHeaders=host;x-amz-date;x-amz-security-token, Signature=9cba1c499417655c170f5018b577b9f89154cf9b9827273df54bfa182e5f4273',
                    'x-amz-security-token': 'GHI'}

        self.assertEqual(expected, headers)

        pass


class TestRequestResponse(TestCase):
    maxDiff = None

    @patch('awscurl.awscurl.__send_request')
    def test_make_request(self, mocked_resp):
        resp = Response()
        resp.status_code=200
        resp._content = b'{"file_name": "test.yml", "env": "staging", "hash": "\xe5\xad\x97"}'
        resp.encoding = 'UTF-8'
        mocked_resp.return_value = resp

        headers = {}
        params = {'method': 'GET',
                  'service': 'ec2',
                  'region': 'region',
                  'uri': 'https://user:pass@host:123/path/?a=b&c=d',
                  'headers': headers,
                  'data': b'C\xcfI\x91\xc1\xd0\tw<\xa8\x13\x06{=\x9b\xb3\x1c\xfcl\xfe\xb9\xb18zS\xf4%i*Q\xc9v',
                  'access_key': '',
                  'secret_key': '',
                  'security_token': '',
                  'data_binary': True}
        r = make_request(**params)

        expected = u'\u5b57'

        ### assert that the unicode character is in the response.text output
        self.assertTrue(expected in r.text)

        ### assert that the unicode character is _not_ in the response.text.encode('utf-8')
        ### which has been converted to 8-bit string with unicode characters escaped
        ### in py2 this raises an exception on the assertion (`expected in x` below)
        ### in py3 we can compare the two directly, and the assertion should be false
        if sys.version_info[0] == 2:
            with self.assertRaises(UnicodeDecodeError):
                x = str(r.text.encode('utf-8'))
                expected in x
        else:
            self.assertFalse(expected in str(r.text.encode('utf-8')))

        pass


class TestAwsUrlEncode(TestCase):
    def test_aws_url_encode(self):
        self.assertEqual(aws_url_encode(""), "")
        self.assertEqual(aws_url_encode("AZaz09-_.~"), "AZaz09-_.~")
        self.assertEqual(aws_url_encode(" /:@[`{"), "%20%2F%3A%40%5B%60%7B")
        self.assertEqual(aws_url_encode("a=,=b"), "a==%2C==b")
        self.assertEqual(aws_url_encode("\u0394-\u30a1"), "%CE%94-%E3%82%A1")

    pass
