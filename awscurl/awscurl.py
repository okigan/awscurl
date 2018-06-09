#!/usr/bin/env python
from __future__ import print_function

import configparser
import datetime
import hashlib
import hmac
import os
import pprint
import re
import sys

import configargparse
import requests

__author__ = 'iokulist'

is_verbose = False


def __log(*args, **kwargs):
    if not is_verbose:
        return
    pp = pprint.PrettyPrinter(stream=sys.stderr)
    pp.pprint(*args, **kwargs)


def __url_path_to_dict(path):
    """http://stackoverflow.com/a/17892757/142207"""

    pattern = (r'^'
               r'((?P<schema>.+?)://)?'
               r'((?P<user>.+?)(:(?P<password>.*?))?@)?'
               r'(?P<host>.*?)'
               r'(:(?P<port>\d+?))?'
               r'(?P<path>/.*?)?'
               r'(\?(?P<query>.*?))?'
               r'$'
               )
    regex = re.compile(pattern)
    m = regex.match(path)
    d = m.groupdict() if m is not None else None

    if d['path'] is None:
        d['path'] = '/'

    if d['query'] is None:
        d['query'] = ''

    return d


def make_request(method,
                 service,
                 region,
                 uri,
                 headers,
                 data,
                 access_key,
                 secret_key,
                 security_token,
                 data_binary):
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

    See also: http://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
    """

    uri_dict = __url_path_to_dict(uri)
    host = uri_dict['host']
    query = uri_dict['query']
    canonical_uri = uri_dict['path']
    port = uri_dict['port']

    def sign(key, msg):
        """
        Key derivation functions.
        See: http://docs.aws.amazon.com
        /general/latest/gr/signature-v4-examples.html
        #signature-v4-examples-python
        """
        return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

    def get_signature_key(key, date_stamp, region_name, service_name):
        k_date = sign(('AWS4' + key).encode('utf-8'), date_stamp)
        k_region = sign(k_date, region_name)
        k_service = sign(k_region, service_name)
        k_signing = sign(k_service, 'aws4_request')
        return k_signing

    def sha256_hash(val):
        return hashlib.sha256(val.encode('utf-8')).hexdigest()

    def sha256_binary_hash(val):
        return hashlib.sha256(val).hexdigest()

    # Create a date for headers and the credential string
    t = __now()
    amzdate = t.strftime('%Y%m%dT%H%M%SZ')
    datestamp = t.strftime('%Y%m%d')  # Date w/o time, used in credential scope

    # ************* TASK 1: CREATE A CANONICAL REQUEST *************
    # http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html

    # Step 1 is to define the verb (GET, POST, etc.)--already done.

    # Step 2: Create canonical URI--the part of the URI from domain to query
    # string (use '/' if no path)
    # canonical_uri = '/'

    # Step 3: Create the canonical query string. In this example (a GET
    # request),
    # request parameters are in the query string. Query string values must
    # be URL-encoded (space=%20). The parameters must be sorted by name.
    # For this example, the query string is pre-formatted in the
    # request_parameters variable.
    canonical_querystring = __normalize_query_string(query)
    __log(canonical_querystring)

    fullhost = host
    if port:
        fullhost = host + ':' + port
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
    payload_hash = sha256_binary_hash(data) if data_binary else sha256_hash(data)

    # Step 7: Combine elements to create create canonical request
    canonical_request = (method + '\n' +
                         requests.utils.quote(canonical_uri) + '\n' +
                         canonical_querystring + '\n' +
                         canonical_headers + '\n' +
                         signed_headers + '\n' +
                         payload_hash)

    __log('\nCANONICAL REQUEST = ' + canonical_request)
    # ************* TASK 2: CREATE THE STRING TO SIGN*************
    # Match the algorithm to the hashing algorithm you use, either SHA-1 or
    # SHA-256 (recommended)
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
    # ************* TASK 3: CALCULATE THE SIGNATURE *************
    # Create the signing key using the function defined above.
    signing_key = get_signature_key(secret_key, datestamp, region, service)

    # Sign the string_to_sign using the signing_key
    encoded = string_to_sign.encode('utf-8')
    signature = hmac.new(signing_key, encoded, hashlib.sha256).hexdigest()

    # ************* TASK 4: ADD SIGNING INFORMATION TO THE REQUEST ***********
    # The signing information can be either in a query string value or in
    # a header named Authorization. This code shows how to use a header.
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
    headers.update({
        'Authorization': authorization_header,
        'x-amz-date': amzdate,
        'x-amz-security-token': security_token,
        'x-amz-content-sha256': payload_hash
    })

    return __send_request(uri, data, headers, method)


def __normalize_query_string(query):
    kv = (list(map(str.strip, s.split("=")))
          for s in query.split('&')
          if len(s) > 0)

    normalized = '&'.join('%s=%s' % (p[0], p[1] if len(p) > 1 else '')
                          for p in sorted(kv))
    return normalized


def __now():
    return datetime.datetime.utcnow()


def __send_request(uri, data, headers, method):
    __log('\nHEADERS++++++++++++++++++++++++++++++++++++')
    __log(headers)

    __log('\nBEGIN REQUEST++++++++++++++++++++++++++++++++++++')
    __log('Request URL = ' + uri)

    r = requests.request(method, uri, headers=headers, data=data)

    __log('\nRESPONSE++++++++++++++++++++++++++++++++++++')
    __log('Response code: %d\n' % r.status_code)

    return r


def load_aws_config(access_key, secret_key, security_token, credentials_path, profile):
    if access_key is None or secret_key is None or security_token is None:
        try:
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

        except configparser.NoSectionError as e:
            __log('AWS profile \'{0}\' not found'.format(e.args))
            raise e
        except configparser.NoOptionError as e:
            __log('AWS profile \'{0}\' is missing \'{1}\''.format(profile, e.args))
            raise e
        except ValueError as e:
            __log(e)
            raise e

    return access_key, secret_key, security_token


def main():
    # note EC2 ignores Accept header and responds in xml
    default_headers = ['Accept: application/xml',
                       'Content-Type: application/json']

    parser = configargparse.ArgumentParser(
        description='Curl AWS request signing',
        formatter_class=configargparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument('-v', '--verbose', action='store_true',
                        help='verbose flag', default=False)
    parser.add_argument('-X', '--request',
                        help='Specify request command to use',
                        default='GET')
    parser.add_argument('-d', '--data', help='HTTP POST data', default='')
    parser.add_argument('-H', '--header', help='HTTP header', action='append')

    parser.add_argument('--data-binary', action='store_true',
                        help='Process HTTP POST data exactly as specified with '
                             'no extra processing whatsoever.', default=False)

    parser.add_argument('--region', help='AWS region', default='us-east-1', env_var='AWS_DEFAULT_REGION')
    parser.add_argument('--profile', help='AWS profile', default='default', env_var='AWS_PROFILE')
    parser.add_argument('--service', help='AWS service', default='execute-api')
    parser.add_argument('--access_key', env_var='AWS_ACCESS_KEY_ID')
    parser.add_argument('--secret_key', env_var='AWS_SECRET_ACCESS_KEY')
    parser.add_argument('--security_token', env_var='AWS_SECURITY_TOKEN')
    parser.add_argument('--session_token', env_var='AWS_SESSION_TOKEN')

    parser.add_argument('uri')

    args = parser.parse_args()
    global is_verbose
    is_verbose = args.verbose

    if args.verbose:
        __log(vars(parser.parse_args()))

    data = args.data

    if data is not None and data.startswith("@"):
        filename = data[1:]
        with open(filename, "r") as f:
            data = f.read()

    if args.header is None:
        args.header = default_headers

    headers = {k: v for (k, v) in map(lambda s: s.split(": "), args.header)}

    credentials_path = os.path.expanduser("~") + "/.aws/credentials"
    args.access_key, args.secret_key, args.security_token = load_aws_config(args.access_key,
                                                                            args.secret_key,
                                                                            args.security_token,
                                                                            credentials_path,
                                                                            args.profile)

    if args.access_key is None:
        raise ValueError('No access key is available')

    if args.secret_key is None:
        raise ValueError('No secret key is available')

    r = make_request(args.request,
                     args.service,
                     args.region,
                     args.uri,
                     headers,
                     data,
                     args.access_key,
                     args.secret_key,
                     args.security_token or args.session_token,
                     args.binary_payload
                     )

    print(r.text)

    r.raise_for_status()

    return 0


if __name__ == '__main__':
    sys.exit(main())
