#!/usr/bin/env python

import datetime
import logging

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
              'data': 'C\xcfI\x91\xc1\xd0\tw<\xa8\x13\x06{=\x9b\xb3\x1c\xfcl\xfe\xb9\xb18zS\xf4%i*Q\xc9v',
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
                  'data': 'C\xcfI\x91\xc1\xd0\tw<\xa8\x13\x06{=\x9b\xb3\x1c\xfcl\xfe\xb9\xb18zS\xf4%i*Q\xc9v',
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
