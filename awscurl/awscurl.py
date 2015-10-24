#!/usr/bin/env python

__author__ = 'iokulist'

import argparse
import re
import os
import datetime
import hashlib
import hmac
import sys

import requests


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
                 access_key,
                 secret_key,
                 security_token):
    """
    # AWS Version 4 signing example

    # EC2 API (DescribeRegions)

    # See: http://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
    # This version makes a GET request and passes the signature
    # in the Authorization header.
    """
    uri_dict = url_path_to_dict(uri)
    host = uri_dict['host']
    query = uri_dict['query']
    canonical_uri = uri_dict['path']

    # ************* REQUEST VALUES *************
    # method = 'GET'
    # service = 'ec2'
    # host = 'ec2.amazonaws.com'
    # region = 'us-east-1'
    # endpoint = 'https://ec2.amazonaws.com'
    # request_parameters = 'Action=DescribeRegions&Version=2013-10-15'

    # Key derivation functions. See:
    # http://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html#signature-v4-examples-python
    def sign(key, msg):
        return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

    def getSignatureKey(key, dateStamp, regionName, serviceName):
        kDate = sign(('AWS4' + key).encode('utf-8'), dateStamp)
        kRegion = sign(kDate, regionName)
        kService = sign(kRegion, serviceName)
        kSigning = sign(kService, 'aws4_request')
        return kSigning

    # Read AWS access key from env. variables or configuration file. Best practice is NOT
    # to embed credentials in code.
    # access_key = os.environ.get('AWS_ACCESS_KEY_ID')
    # secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
    if access_key is None or secret_key is None:
        print('No access key is available.')
        return

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

    # Step 3: Create the canonical query string. In this example (a GET request),
    # request parameters are in the query string. Query string values must
    # be URL-encoded (space=%20). The parameters must be sorted by name.
    # For this example, the query string is pre-formatted in the request_parameters variable.
    canonical_querystring = query if query is not None else ''

    # Step 4: Create the canonical headers and signed headers. Header names
    # and value must be trimmed and lowercase, and sorted in ASCII order.
    # Note that there is a trailing \n.
    canonical_headers = 'host:' + host + '\n' + 'x-amz-date:' + amzdate + '\n'

    # Step 5: Create the list of signed headers. This lists the headers
    # in the canonical_headers list, delimited with ";" and in alpha order.
    # Note: The request can include any headers; canonical_headers and
    # signed_headers lists those that you want to be included in the
    # hash of the request. "Host" and "x-amz-date" are always required.
    signed_headers = 'host;x-amz-date'

    # Step 6: Create payload hash (hash of the request body content). For GET
    # requests, the payload is an empty string ("").
    payload_hash = hashlib.sha256(data).hexdigest()

    # Step 7: Combine elements to create create canonical request
    canonical_request = method + '\n' + \
                        canonical_uri + '\n' + \
                        canonical_querystring + '\n' + \
                        canonical_headers + '\n' + \
                        signed_headers + '\n' + \
                        payload_hash

    # ************* TASK 2: CREATE THE STRING TO SIGN*************
    # Match the algorithm to the hashing algorithm you use, either SHA-1 or
    # SHA-256 (recommended)
    algorithm = 'AWS4-HMAC-SHA256'
    credential_scope = datestamp + '/' + region + '/' + service + '/' + 'aws4_request'
    string_to_sign = algorithm + '\n' + \
                     amzdate + '\n' + \
                     credential_scope + '\n' + \
                     hashlib.sha256(canonical_request).hexdigest()

    # ************* TASK 3: CALCULATE THE SIGNATURE *************
    # Create the signing key using the function defined above.
    signing_key = getSignatureKey(secret_key, datestamp, region, service)

    # Sign the string_to_sign using the signing_key
    signature = hmac.new(signing_key, (string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()

    # ************* TASK 4: ADD SIGNING INFORMATION TO THE REQUEST *************
    # The signing information can be either in a query string value or in
    # a header named Authorization. This code shows how to use a header.
    # Create authorization header and add to request headers
    authorization_header = algorithm + ' ' + \
                           'Credential=' + access_key + '/' + credential_scope + ', ' + \
                           'SignedHeaders=' + signed_headers + ', ' + \
                           'Signature=' + signature

    # The request can include any headers, but MUST include "host", "x-amz-date",
    # and (for this scenario) "Authorization". "host" and "x-amz-date" must
    # be included in the canonical_headers and signed_headers, as noted
    # earlier. Order here is not significant.
    # Python note: The 'host' header is added automatically by the Python 'requests' library.
    headers.update({
        'x-amz-date': amzdate,
        'Authorization': authorization_header,
        'x-amz-security-token': security_token
    })

    # ************* SEND THE REQUEST *************
    send_request(uri, data, headers, method)


def now():
    return datetime.datetime.utcnow()


def send_request(args_uri, data, headers, method):
    print('\nBEGIN REQUEST++++++++++++++++++++++++++++++++++++')
    print('Request URL = ' + args_uri)
    r = None
    if method == 'GET':
        r = requests.get(args_uri, headers=headers)
    elif method == 'POST':
        r = requests.post(args_uri, headers=headers, data=data)
    print('\nRESPONSE++++++++++++++++++++++++++++++++++++')
    print('Response code: %d\n' % r.status_code)
    print(r.text)


def main():
    default_headers = ['Accept: application/json',
                       'Content-Type: application/json']

    parser = argparse.ArgumentParser(description='Demo')

    parser.add_argument('-v', '--verbose', action='store_true', help='verbose flag', )
    parser.add_argument('-X', '--request', help='Specify request command to use', )
    parser.add_argument('-d', '--data', help='HTTP POST data', default='')
    parser.add_argument('-H', '--header', help='HTTP POST data', action='append')

    parser.add_argument('--region', help='AWS region', default='us-east-1')
    parser.add_argument('--service', help='AWS service', default='execute-api')
    parser.add_argument('--access_key', default=os.environ.get('AWS_ACCESS_KEY_ID'))
    parser.add_argument('--secret_key', default=os.environ.get('AWS_SECRET_ACCESS_KEY'))
    parser.add_argument('--security_token', default=os.environ.get('AWS_SECURITY_TOKEN'))

    parser.add_argument('uri')

    args = parser.parse_args()

    if args.verbose:
        print(args)

    data = args.data

    if data is not None and data.startswith("@"):
        filename = data[1:]
        with open(filename, "r") as f:
            data = f.read()

    if args.header is None:
        args.header = default_headers

    headers = dict(s.split(": ") for s in args.header)

    request = args.request
    service = args.service
    region = args.region

    key = args.access_key
    secret_key = args.secret_key
    token = args.security_token

    uri = args.uri

    make_request(request,
                 service,
                 region,
                 uri,
                 headers,
                 data,
                 key,
                 secret_key,
                 token
                 )


if __name__ == '__main__':
    sys.exit(main())
