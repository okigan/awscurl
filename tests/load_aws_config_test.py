#!/usr/bin/env python

import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import TestCase

import mock

from awscurl.awscurl import load_aws_config

__author__ = "iokulist"


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

    def test_credential_process(self):
        expire_dt = datetime.now(tz=timezone.utc) + timedelta(seconds=10)
        test_creds = {
            "Version": 1,
            "AccessKeyId": "testAccessKeyId",
            "SecretAccessKey": "testSecretAccessKey",
            "SessionToken": "testSessionToken",
            #
            "Expiration": expire_dt.isoformat(timespec="seconds"),
        }

        with tempfile.TemporaryDirectory() as tmp_dir:
            creds_str = json.dumps(test_creds)
            creds_file = Path(tmp_dir) / "config"
            with creds_file.open("w") as fp:
                fp.write(f"""
                [profile tester]
                credential_process=echo '{creds_str}'
                """)
            with mock.patch.dict("os.environ", {"AWS_CONFIG_FILE": str(creds_file)}):
                access_key, secret_access, token = load_aws_config(
                    None, None, None, "./tests/data/credentials", "tester"
                )
                self.assertEqual(
                    [access_key, secret_access, token],
                    [
                        test_creds["AccessKeyId"],
                        test_creds["SecretAccessKey"],
                        test_creds["SessionToken"],
                    ],
                )
