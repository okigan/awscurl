#!/usr/bin/env python
"""
Awscurl implementation
"""
from __future__ import print_function

import datetime
import hashlib
import hmac
import os
import pprint
import sys
import re

import configparser
import configargparse
import requests
from requests.structures import CaseInsensitiveDict


from .utils import sha256_hash, sha256_hash_for_binary_data, sign

__author__ = 'iokulist'

IS_VERBOSE = False


def __log(*args, **kwargs):
    if not IS_VERBOSE:
        return
    stderr_pp = pprint.PrettyPrinter(stream=sys.stderr)
    stderr_pp.pprint(*args, **kwargs)


def url_path_to_dict(path):
    """http://stackoverflow.com/a/17892757/142207"""

    pattern = (r'^'
               r'((?P<schema>.+?)://)?'
               r'((?P<user>[^/]+?)(:(?P<password>[^/]*?))?@)?'
               r'(?P<host>.*?)'
               r'(:(?P<port>\d+?))?'
               r'(?P<path>/.*?)?'
               r'(\?(?P<query>.*?))?'
               r'$')
    regex = re.compile(pattern)
    url_match = regex.match(path)
    url_dict = url_match.groupdict() if url_match is not None else None

    if url_dict['path'] is None:
        url_dict['path'] = '/'

    if url_dict['query'] is None:
        url_dict['query'] = ''

    return url_dict


# pylint: disable=too-many-arguments,too-many-locals
def make_request(method,
                 service,
                 region,
                 uri,
                 headers,
                 data,
                 access_key,
                 secret_key,
                 security_token,
                 data_binary,
                 verify=True):
    """
    # Make HTTP request with AWS Version 4 signing

    :return: http request object
    :param method: str
    :param service: str
    :param region: str
    :param uri: str
    :param headers: dict
    :param data: str
    :param profile: str
    :param access_key: str
    :param secret_key: str
    :param security_token: str
    :param data_binary: bool
    :param verify: bool

    See also: http://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
    """

    uri_dict = url_path_to_dict(uri)
    host = uri_dict['host']
    query = uri_dict['query']
    canonical_uri = uri_dict['path']
    port = uri_dict['port']

    # Create a date for headers and the credential string
    current_time = __now()
    amzdate = current_time.strftime('%Y%m%dT%H%M%SZ')
    datestamp = current_time.strftime('%Y%m%d')  # Date w/o time, used in credential scope

    canonical_request, payload_hash, signed_headers = task_1_create_a_canonical_request(
        query,
        headers,
        port,
        host,
        amzdate,
        method,
        data,
        security_token,
        data_binary,
        canonical_uri)
    string_to_sign, algorithm, credential_scope = task_2_create_the_string_to_sign(
        amzdate,
        datestamp,
        canonical_request,
        service,
        region)
    signature = task_3_calculate_the_signature(
        datestamp,
        string_to_sign,
        service,
        region,
        secret_key)
    auth_headers = task_4_build_auth_headers_for_the_request(
        amzdate,
        payload_hash,
        algorithm,
        credential_scope,
        signed_headers,
        signature,
        access_key,
        security_token)
    headers.update(auth_headers)

    return __send_request(uri, data, headers, method, verify)


# pylint: disable=too-many-arguments,too-many-locals
def task_1_create_a_canonical_request(
        query,
        headers,
        port,
        host,
        amzdate,
        method,
        data,
        security_token,
        data_binary,
        canonical_uri):
    """
    ************* TASK 1: CREATE A CANONICAL REQUEST *************
    http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html

    Step 1 is to define the verb (GET, POST, etc.)--already done.

    Step 2: Create canonical URI--the part of the URI from domain to query
    string (use '/' if no path)
    canonical_uri = '/'

    Step 3: Create the canonical query string. In this example (a GET
    request),
    request parameters are in the query string. Query string values must
    be URL-encoded (space=%20). The parameters must be sorted by name.
    For this example, the query string is pre-formatted in the
    request_parameters variable.
    """
    canonical_querystring = __normalize_query_string(query)
    __log(canonical_querystring)

    # If the host was specified in the HTTP header, ensure that the canonical
    # headers are set accordingly
    if 'host' in headers:
        fullhost = headers['host']
    else:
        fullhost = host + ':' + port if port else host

    # Step 4: Create the canonical headers and signed headers. Header names
    # and value must be trimmed and lowercase, and sorted in ASCII order.
    # Note that there is a trailing \n.
    canonical_headers = ('host:' + fullhost + '\n' +
                         'x-amz-date:' + amzdate + '\n')

    if security_token:
        canonical_headers += ('x-amz-security-token:' + security_token + '\n')

    # Step 5: Create the list of signed headers. This lists the headers
    # in the canonical_headers list, delimited with ";" and in alpha order.
    # Note: The request can include any headers; canonical_headers and
    # signed_headers lists those that you want to be included in the
    # hash of the request. "Host" and "x-amz-date" are always required.
    signed_headers = 'host;x-amz-date'

    if security_token:
        signed_headers += ';x-amz-security-token'

    # Step 6: Create payload hash (hash of the request body content). For GET
    # requests, the payload is an empty string ("").
    payload_hash = sha256_hash_for_binary_data(data) if data_binary else sha256_hash(data)

    # Step 7: Combine elements to create create canonical request
    canonical_request = (method + '\n' +
                         requests.utils.quote(canonical_uri) + '\n' +
                         canonical_querystring + '\n' +
                         canonical_headers + '\n' +
                         signed_headers + '\n' +
                         payload_hash)

    __log('\nCANONICAL REQUEST = ' + canonical_request)
    return canonical_request, payload_hash, signed_headers


def task_2_create_the_string_to_sign(
        amzdate,
        datestamp,
        canonical_request,
        service,
        region):
    """
    ************* TASK 2: CREATE THE STRING TO SIGN*************
    Match the algorithm to the hashing algorithm you use, either SHA-1 or
    SHA-256 (recommended)
    """
    algorithm = 'AWS4-HMAC-SHA256'
    credential_scope = (datestamp + '/' +
                        region + '/' +
                        service + '/' +
                        'aws4_request')
    string_to_sign = (algorithm + '\n' +
                      amzdate + '\n' +
                      credential_scope + '\n' +
                      sha256_hash(canonical_request))

    __log('\nSTRING_TO_SIGN = ' + string_to_sign)
    return string_to_sign, algorithm, credential_scope


def task_3_calculate_the_signature(
        datestamp,
        string_to_sign,
        service,
        region,
        secret_key):
    """
    ************* TASK 3: CALCULATE THE SIGNATURE *************
    """

    def get_signature_key(key, date_stamp, region_name, service_name):
        """
        See: https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html

        In AWS Signature Version 4, instead of using your AWS access keys to sign a request, you
        first create a signing key that is scoped to a specific region and service.  For more
        information about signing keys, see Introduction to Signing Requests.
        """
        k_date = sign(('AWS4' + key).encode('utf-8'), date_stamp)
        k_region = sign(k_date, region_name)
        k_service = sign(k_region, service_name)
        k_signing = sign(k_service, 'aws4_request')
        return k_signing

    # Create the signing key using the function defined above.
    signing_key = get_signature_key(secret_key, datestamp, region, service)

    # Sign the string_to_sign using the signing_key
    encoded = string_to_sign.encode('utf-8')
    signature = hmac.new(signing_key, encoded, hashlib.sha256).hexdigest()
    return signature


def task_4_build_auth_headers_for_the_request(
        amzdate,
        payload_hash,
        algorithm,
        credential_scope,
        signed_headers,
        signature,
        access_key,
        security_token):
    """
    ************* TASK 4: ADD SIGNING INFORMATION TO THE REQUEST ***********
    The signing information can be either in a query string value or in a header
    named Authorization. This function shows how to use the header.  It returns
    a headers dict with all the necessary signing headers.
    """
    # Create authorization header and add to request headers
    authorization_header = (
        algorithm + ' ' +
        'Credential=' + access_key + '/' + credential_scope + ', ' +
        'SignedHeaders=' + signed_headers + ', ' +
        'Signature=' + signature
    )

    # The request can include any headers, but MUST include "host",
    # "x-amz-date", and (for this scenario) "Authorization". "host" and
    # "x-amz-date" must be included in the canonical_headers and
    # signed_headers, as noted earlier. Order here is not significant.
    # Python note: The 'host' header is added automatically by the Python
    # 'requests' library.
    return {
        'Authorization': authorization_header,
        'x-amz-date': amzdate,
        'x-amz-security-token': security_token,
        'x-amz-content-sha256': payload_hash
    }


def __normalize_query_string(query):
    parameter_pairs = (list(map(str.strip, s.split("=")))
                       for s in query.split('&')
                       if len(s) > 0)

    normalized = '&'.join('%s=%s' % (p[0], p[1] if len(p) > 1 else '')
                          for p in sorted(parameter_pairs))
    return normalized


def __now():
    return datetime.datetime.utcnow()


def __send_request(uri, data, headers, method, verify):
    __log('\nHEADERS++++++++++++++++++++++++++++++++++++')
    __log(headers)

    __log('\nBEGIN REQUEST++++++++++++++++++++++++++++++++++++')
    __log('Request URL = ' + uri)

    response = requests.request(method, uri, headers=headers, data=data, verify=verify)

    __log('\nRESPONSE++++++++++++++++++++++++++++++++++++')
    __log('Response code: %d\n' % response.status_code)

    return response


# pylint: disable=too-many-branches
def load_aws_config(access_key, secret_key, security_token, credentials_path, profile):
    # type: (str, str, str, str, str) -> Tuple[str, str, str]
    """
    Load aws credential configuration, by parsing credential file, then try to fall back to
    botocore, by checking (access_key,secret_key) are not (None,None)
    """
    if access_key is None or secret_key is None:
        try:
            exists = os.path.exists(credentials_path)
            __log('Credentials file \'{0}\' exists \'{1}\''.format(credentials_path, exists))

            config = configparser.ConfigParser()
            config.read(credentials_path)

            while True:
                if access_key is None and config.has_option(profile, "aws_access_key_id"):
                    access_key = config.get(profile, "aws_access_key_id")
                else:
                    break

                if secret_key is None and config.has_option(profile, "aws_secret_access_key"):
                    secret_key = config.get(profile, "aws_secret_access_key")
                else:
                    break

                if security_token is None and config.has_option(profile, "aws_session_token"):
                    security_token = config.get(profile, "aws_session_token")

                break

        except configparser.NoSectionError as exception:
            __log('AWS profile \'{0}\' not found'.format(exception.args))
            raise exception
        except configparser.NoOptionError as exception:
            __log('AWS profile \'{0}\' is missing \'{1}\''.format(profile, exception.args))
            raise exception
        except ValueError as exception:
            __log(exception)
            raise exception

    # try to load instance credentials using botocore
    if access_key is None or secret_key is None:
        try:
            __log("loading botocore package")
            import botocore
        except ImportError:
            __log("botocore package could not be loaded")
            botocore = None

        if botocore:
            import botocore.session
            session = botocore.session.get_session()
            cred = session.get_credentials()
            access_key, secret_key, security_token = cred.access_key, cred.secret_key, cred.token

    return access_key, secret_key, security_token


def main():
    """
    Awscurl CLI main entry point
    """
    # note EC2 ignores Accept header and responds in xml
    default_headers = ['Accept: application/xml',
                       'Content-Type: application/json']

    parser = configargparse.ArgumentParser(
        description='Curl AWS request signing',
        formatter_class=configargparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument('-v', '--verbose', action='store_true',
                        help='verbose flag', default=False)
    parser.add_argument('-i', '--include', action='store_true',
                        help='include headers in the output', default=False)
    parser.add_argument('-X', '--request',
                        help='Specify request command to use',
                        default='GET')
    parser.add_argument('-d', '--data', help='HTTP POST data', default='')
    parser.add_argument('-H', '--header', help='HTTP header', action='append')
    parser.add_argument('-k', '--insecure', action='store_false',
                        help='This option allows awscurl to proceed and operate even for server '
                             'connections otherwise considered insecure')

    parser.add_argument('--data-binary', action='store_true',
                        help='Process HTTP POST data exactly as specified with '
                             'no extra processing whatsoever.', default=False)

    parser.add_argument('--region', help='AWS region', default='us-east-1',
                        env_var='AWS_DEFAULT_REGION')
    parser.add_argument('--profile', help='AWS profile', default='default', env_var='AWS_PROFILE')
    parser.add_argument('--service', help='AWS service', default='execute-api')
    parser.add_argument('--access_key', env_var='AWS_ACCESS_KEY_ID')
    parser.add_argument('--secret_key', env_var='AWS_SECRET_ACCESS_KEY')
    # AWS_SECURITY_TOKEN is deprecated, but kept for backward compatibility
    # https://github.com/boto/botocore/blob/c76553d3158b083d818f88c898d8f6d7918478fd/botocore/credentials.py#L260-262
    parser.add_argument('--security_token', env_var='AWS_SECURITY_TOKEN')
    parser.add_argument('--session_token', env_var='AWS_SESSION_TOKEN')

    parser.add_argument('uri')

    args = parser.parse_args()
    # pylint: disable=global-statement
    global IS_VERBOSE
    IS_VERBOSE = args.verbose

    if args.verbose:
        __log(vars(parser.parse_args()))

    data = args.data

    if data is not None and data.startswith("@"):
        filename = data[1:]
        with open(filename, "r") as post_data_file:
            data = post_data_file.read()

    if args.header is None:
        args.header = default_headers

    if args.security_token is not None:
        args.session_token = args.security_token
        del args.security_token

    # pylint: disable=deprecated-lambda
    headers = {k: v for (k, v) in map(lambda s: s.split(": "), args.header)}
    headers = CaseInsensitiveDict(headers)

    credentials_path = os.path.expanduser("~") + "/.aws/credentials"
    args.access_key, args.secret_key, args.session_token = load_aws_config(args.access_key,
                                                                           args.secret_key,
                                                                           args.session_token,
                                                                           credentials_path,
                                                                           args.profile)

    if args.access_key is None:
        raise ValueError('No access key is available')

    if args.secret_key is None:
        raise ValueError('No secret key is available')

    response = make_request(args.request,
                            args.service,
                            args.region,
                            args.uri,
                            headers,
                            data,
                            args.access_key,
                            args.secret_key,
                            args.session_token,
                            args.data_binary,
                            args.insecure)

    if args.include:
        print(response.headers, end='\n\n')
    print(response.text)

    response.raise_for_status()

    return 0


if __name__ == '__main__':
    sys.exit(main())
