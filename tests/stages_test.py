#!/usr/bin/env python
"""
Test cases for seprate header calculation stages.
"""

from unittest import TestCase

from awscurl.awscurl import (
    task_1_create_a_canonical_request,
    task_2_create_the_string_to_sign,
    task_3_calculate_the_signature,
    task_4_build_auth_headers_for_the_request)


class TestStages(TestCase):
    """
    Suite to test all stages.
    """
    maxDiff = None

    def test_task_1_create_a_canonical_request(self):
        """
        Test the function to create the "canonical" request to match the thing that AWS is hashing
        on the server side.
        """
        canonical_request, payload_hash, signed_headers = task_1_create_a_canonical_request(
            query="Action=DescribeInstances&Version=2013-10-15",
            headers="{'Content-Type': 'application/json', 'Accept': 'application/xml'}",
            port=None,
            host="ec2.amazonaws.com",
            amzdate="20190921T022008Z",
            method="GET",
            data="",
            security_token=None,
            data_binary=False,
            canonical_uri="/")
        self.assertEqual(canonical_request, "GET\n"
                         "/\n"
                         "Action=DescribeInstances&Version=2013-10-15\n"
                         "host:ec2.amazonaws.com\n"
                         "x-amz-date:20190921T022008Z\n"
                         "\n"
                         "host;x-amz-date\n"
                         "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        self.assertEqual(payload_hash,
                         "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        self.assertEqual(signed_headers, "host;x-amz-date")

    def test_task_1_create_a_canonical_request_url_encode_querystring(self):
        """
        Test that canonical requests correctly sort and url encode querystring parameters.
        """
        canonical_request, payload_hash, signed_headers = task_1_create_a_canonical_request(
            query="arg1=true&arg3=c,b,a&arg2=false&noEncoding=ABC-abc_1.23~tilde/slash",
            headers="{'Content-Type': 'application/json', 'Accept': 'application/xml'}",
            port=None,
            host="my-gateway-id.execute-api.us-east-1.amazonaws.com",
            amzdate="20190921T022008Z",
            method="GET",
            data="",
            security_token=None,
            data_binary=False,
            canonical_uri="/stage/my-path")
        self.assertEqual(canonical_request, "GET\n"
                         "/stage/my-path\n"
                         "arg1=true&arg2=false&arg3=c%2Cb%2Ca&noEncoding=ABC-abc_1.23~tilde%2Fslash\n"
                         "host:my-gateway-id.execute-api.us-east-1.amazonaws.com\n"
                         "x-amz-date:20190921T022008Z\n"
                         "\n"
                         "host;x-amz-date\n"
                         "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        self.assertEqual(payload_hash,
                         "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        self.assertEqual(signed_headers, "host;x-amz-date")

    def test_task_2_create_the_string_to_sign(self):
        """
        Test the next function that is creating a string in exactly the same way as AWS is on the
        server side, to make sure our signature matches.
        """
        string_to_sign, algorithm, credential_scope = task_2_create_the_string_to_sign(
            amzdate="20190921T022008Z",
            datestamp="20190921",
            canonical_request="GET\n"
            "/\n"
            "Action=DescribeInstances&Version=2013-10-15\n"
            "host:ec2.amazonaws.com\n"
            "x-amz-date:20190921T022008Z\n"
            "\n"
            "host;x-amz-date\n"
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            service="ec2",
            region="us-east-1",
            )
        self.assertEqual(string_to_sign, "AWS4-HMAC-SHA256\n"
                         "20190921T022008Z\n"
                         "20190921/us-east-1/ec2/aws4_request\n"
                         "4a3b77321aca7e671d4945f0b3b826112e5ca3f2a10c4357e54f518798e7c8ff")
        self.assertEqual(algorithm, "AWS4-HMAC-SHA256")
        self.assertEqual(credential_scope, "20190921/us-east-1/ec2/aws4_request")

    def test_task_3_calculate_the_signature(self):
        """
        Test that we calculate the correct signature from our carefully prepared strings.
        """
        signature = task_3_calculate_the_signature(
            datestamp="20190921",
            string_to_sign="AWS4-HMAC-SHA256\n"
            "20190921T022008Z\n"
            "20190921/us-east-1/ec2/aws4_request\n"
            "4a3b77321aca7e671d4945f0b3b826112e5ca3f2a10c4357e54f518798e7c8ff",
            service="ec2",
            region="us-east-1",
            secret_key="dummytestsecretkey",
            )
        self.assertEqual(signature,
                         "9164aea23e266890838ff6e51eea552e2ee39c63896ac61d91990f200bb16362")

    def test_task_4_build_auth_headers_for_the_request(self):
        """
        Test that we are adding the proper headers based on all our calculated information.
        """
        new_headers = task_4_build_auth_headers_for_the_request(
            amzdate="20190921T022008Z",
            payload_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            algorithm="AWS4-HMAC-SHA256",
            credential_scope="20190921/us-east-1/ec2/aws4_request",
            signed_headers="host;x-amz-date",
            signature="9164aea23e266890838ff6e51eea552e2ee39c63896ac61d91990f200bb16362",
            access_key="AKIAIJLPLDILMJV53HCQ",
            security_token=None,
            )
        self.assertEqual(
            new_headers['x-amz-content-sha256'],
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
        self.assertNotIn('x-amz-security-token', new_headers)
        self.assertEqual(
            new_headers['x-amz-date'],
            '20190921T022008Z')
        self.assertEqual(
            new_headers['Authorization'],
            'AWS4-HMAC-SHA256 '
            'Credential=AKIAIJLPLDILMJV53HCQ/20190921/us-east-1/ec2/aws4_request, '
            'SignedHeaders=host;x-amz-date, '
            'Signature=9164aea23e266890838ff6e51eea552e2ee39c63896ac61d91990f200bb16362')
