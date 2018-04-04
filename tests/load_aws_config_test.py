#!/usr/bin/env python


from unittest import TestCase

from awscurl.awscurl import load_aws_config

__author__ = 'iokulist'


class Test__load_aws_config(TestCase):
    def test(self):
        access_key, secret_access, token = load_aws_config(None,
                                                           None,
                                                           None,
                                                           "./tests/data/credentials",
                                                           "default")

        self.assertEquals([access_key, secret_access, token], ['access_key_id', 'secret_access_key', None])

        access_key, secret_access, token = load_aws_config(None,
                                                           None,
                                                           "ttt",
                                                           "./tests/data/credentials",
                                                           "default")

        self.assertEquals([access_key, secret_access, token], ['access_key_id', 'secret_access_key', 'ttt'])

        access_key, secret_access, token = load_aws_config('aaa',
                                                           None,
                                                           "ttt",
                                                           "./tests/data/credentials",
                                                           "default")

        self.assertEquals([access_key, secret_access, token], ['aaa', None, 'ttt'])
