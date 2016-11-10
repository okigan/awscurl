#!/usr/bin/env python
from __future__ import print_function
from os.path import expanduser

import re
import datetime
import hashlib
import hmac
import sys
import pprint

import configargparse
import configparser
import requests

__author__ = 'iokulist'


def log(*args, **kwargs):
    pp = pprint.PrettyPrinter(stream=sys.stderr)
    pp.pprint(*args, **kwargs)


def url_path_to_dict(path):
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
                 profile,
                 access_key,
                 secret_key,
                 security_token):
    """
    # Make HTTP request with AWS Version 4 signing

    :param method: str
    :param service: str
    :param region: str
    :param uri: str
    :param headers: dict
    :param data:str
    :param profile: str
    :param access_key: str
    :param secret_key: str
    :param security_token: str

    See also: http://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
    """

    uri_dict = url_path_to_dict(uri)
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

    if access_key is None or secret_key is None:
        try:
            config = configparser.ConfigParser()
            config.read(expanduser("~") + "/.aws/credentials")

            access_key = access_key or config.get(profile, "aws_access_key_id")
            secret_key = secret_key or config.get(profile,
                                                  "aws_secret_access_key")

            if access_key is None or secret_key is None:
                raise ValueError('No access key is available')
        except configparser.NoSectionError:
            log('AWS profile \'{0}\' not found'.format(profile))
            return 1
        except configparser.NoOptionError:
            log('AWS profile \'{0}\' is missing access or secret key'
                .format(profile))
            return 1
        except ValueError as error:
            log(error)
            return 1

    # Create a date for headers and the credential string
    t = now()
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
    canonical_querystring = normalize_query_string(query)
    log(canonical_querystring)

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
    payload_hash = hashlib.sha256(data).hexdigest()

    # Step 7: Combine elements to create create canonical request
    canonical_request = (method + '\n' +
                         canonical_uri + '\n' +
                         canonical_querystring + '\n' +
                         canonical_headers + '\n' +
                         signed_headers + '\n' +
                         payload_hash)

    log('\nCANONICAL REQUEST = ' + canonical_request)
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
                      hashlib.sha256(canonical_request).hexdigest())

    log('\nSTRING_TO_SIGN = ' + string_to_sign)
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

    return send_request(uri, data, headers, method)


def normalize_query_string(query):
    kv = (map(str.strip, s.split("="))
          for s in query.split('&')
          if len(s) > 0)

    normalized = '&'.join('%s=%s' % (p[0], p[1] if len(p) > 1 else '')
                          for p in sorted(kv))
    return normalized


def now():
    return datetime.datetime.utcnow()


def send_request(uri, data, headers, method):
    log('\nHEADERS++++++++++++++++++++++++++++++++++++')
    log(headers)

    log('\nBEGIN REQUEST++++++++++++++++++++++++++++++++++++')
    log('Request URL = ' + uri)

    r = requests.request(method, uri, headers=headers, data=data)

    log('\nRESPONSE++++++++++++++++++++++++++++++++++++')
    log('Response code: %d\n' % r.status_code)
    print(r.content)

    r.raise_for_status()

    return 0


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

    parser.add_argument('--region', help='AWS region', default='us-east-1')
    parser.add_argument('--profile',
                        help='AWS profile',
                        default='default',
                        env_var='AWS_PROFILE')
    parser.add_argument('--service',
                        help='AWS service',
                        default='execute-api')
    parser.add_argument('--access_key', env_var='AWS_ACCESS_KEY_ID')
    parser.add_argument('--secret_key', env_var='AWS_SECRET_ACCESS_KEY')
    parser.add_argument('--security_token', env_var='AWS_SECURITY_TOKEN')

    parser.add_argument('uri')

    args = parser.parse_args()

    if args.verbose:
        log(vars(parser.parse_args()))

    data = args.data

    if data is not None and data.startswith("@"):
        filename = data[1:]
        with open(filename, "r") as f:
            data = f.read()

    if args.header is None:
        args.header = default_headers

    headers = {k: v for (k, v) in map(lambda s: s.split(": "), args.header)}

    return make_request(args.request,
                        args.service,
                        args.region,
                        args.uri,
                        headers,
                        data,
                        args.profile,
                        args.access_key,
                        args.secret_key,
                        args.security_token
                        )


if __name__ == '__main__':
    sys.exit(main())
