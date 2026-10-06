#!/usr/bin/env python

import json
import os
import sys
import tempfile
from unittest import TestCase, mock

from awscurl.awscurl import load_aws_config

__author__ = 'iokulist'


class Test__load_aws_config(TestCase):
    def test(self):
        access_key, secret_access, token = load_aws_config(None,
                                                           None,
                                                           None,
                                                           "./tests/data/credentials",
                                                           "default")

        self.assertEqual([access_key, secret_access, token], ['access_key_id', 'secret_access_key', None])

        access_key, secret_access, token = load_aws_config(None,
                                                           None,
                                                           "ttt",
                                                           "./tests/data/credentials",
                                                           "default")

        self.assertEqual([access_key, secret_access, token], ['access_key_id', 'secret_access_key', 'ttt'])

        # TODO: remove this test as I think it's not valid to loads secret_key if session_key was already provided
        # access_key, secret_access, token = load_aws_config('aaa',
        #                                                    None,
        #                                                    "ttt",
        #                                                    "./tests/data/credentials",
        #                                                    "default")
        #
        # self.assertEquals([access_key, secret_access, token], ['aaa', None, 'ttt'])


def _clean_aws_env(**overrides):
    env = {k: v for k, v in os.environ.items() if not k.startswith('AWS_')}
    env.update(overrides)
    return mock.patch.dict(os.environ, env, clear=True)


class Test__load_aws_config_botocore_profile(TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _path(self, name, content):
        path = os.path.join(self.tmp.name, name)
        with open(path, 'w') as f:
            f.write(content)
        return path

    def test_credential_process_profile_is_used(self):
        creds = {'Version': 1,
                 'AccessKeyId': 'process_access_key',
                 'SecretAccessKey': 'process_secret_key',
                 'SessionToken': 'process_token'}
        script = self._path('creds.py', 'print({0!r})\n'.format(json.dumps(creds)))
        config = self._path('config', '[profile tester]\ncredential_process = "{0}" "{1}"\n'.format(
            sys.executable, script))
        credentials = self._path('credentials',
                                 '[default]\naws_access_key_id = stale_access_key\n'
                                 'aws_secret_access_key = stale_secret_key\n')

        with _clean_aws_env(AWS_CONFIG_FILE=config, AWS_SHARED_CREDENTIALS_FILE=credentials):
            result = load_aws_config(None, None, None, credentials, 'tester')

        self.assertEqual(list(result), ['process_access_key', 'process_secret_key', 'process_token'])

    def test_default_profile_without_config_uses_env_credentials(self):
        missing = os.path.join(self.tmp.name, 'missing')

        with _clean_aws_env(AWS_CONFIG_FILE=missing, AWS_SHARED_CREDENTIALS_FILE=missing,
                            AWS_ACCESS_KEY_ID='env_access_key', AWS_SECRET_ACCESS_KEY='env_secret_key'):
            result = load_aws_config(None, None, None, missing, 'default')

        self.assertEqual(list(result), ['env_access_key', 'env_secret_key', None])
