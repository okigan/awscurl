#!/usr/bin/env python


from unittest import TestCase

from awscurl import awscurl

__author__ = 'iokulist'


class TestUriParsing(TestCase):
    maxDiff = None

    def test(self, *args, **kvargs):
        self.assertEqual(awscurl.url_path_to_dict("http://google.com"),
                         {'host': 'google.com',
                          'password': None,
                          'path': '/',
                          'port': None,
                          'query': '',
                          'schema': 'http',
                          'user': None})

        self.assertEqual(awscurl.url_path_to_dict("http://user:password@google.com"),
                         {'host': 'google.com',
                          'password': 'password',
                          'path': '/',
                          'port': None,
                          'query': '',
                          'schema': 'http',
                          'user': 'user'})

        self.assertEqual(awscurl.url_path_to_dict("http://user:password@google.com/path1/path2"),
                         {'host': 'google.com',
                          'password': 'password',
                          'path': '/path1/path2',
                          'port': None,
                          'query': '',
                          'schema': 'http',
                          'user': 'user'})

        self.assertEqual(awscurl.url_path_to_dict("http://google.com/path1/path2/@weird"),
                         {'host': 'google.com',
                          'password': None,
                          'path': '/path1/path2/@weird',
                          'port': None,
                          'query': '',
                          'schema': 'http',
                          'user': None})

