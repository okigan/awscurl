awscurl
=======

Curl like tool with AWS Signature Version 4 request signing. |Build
Status|

Overview
--------

Requests to AWS API must be signed (see `Signing AWS API
Requests <http://docs.aws.amazon.com/general/latest/gr/signing_aws_api_requests.html>`__)
automates the process of signing and allows to make requests to AWS as
simple as standard curl command.

Installation
------------

``sh   $ pip install awscurl``

Examples
--------

-  Call S3: List bucket content
   ``sh   $ awscurl.py --service s3 https://okigan-lambdapics.s3.amazonaws.com``

-  Call EC2:
   ``sh   $ awscurl --service ec2 'https://ec2.amazonaws.com?Action=DescribeRegions&Version=2013-10-15'``

-  Call API Gateway:
   ``sh   $ awscurl --service execute-api -X POST -d @request.json \ https://<prefix>.execute-api.us-east-1.amazonaws.com/<resource>``

Options
-------

::

    usage: awscurl.py [-h] [-v] [-X REQUEST] [-d DATA] [-H HEADER]
                      [--region REGION] [--service SERVICE]
                      [--access_key ACCESS_KEY] [--secret_key SECRET_KEY]
                      [--security_token SECURITY_TOKEN]
                      uri

    Curl AWS request signing If an arg is specified in more than one place, then
    command-line values override environment variables which override defaults.

    positional arguments:
      uri

    optional arguments:
      -h, --help            show this help message and exit
      -v, --verbose         verbose flag (default: False)
      -X REQUEST, --request REQUEST
                            Specify request command to use (default: GET)
      -d DATA, --data DATA  HTTP POST data (default: )
      -H HEADER, --header HEADER
                            HTTP POST data (default: None)
      --region REGION       AWS region (default: us-east-1)
      --service SERVICE     AWS service (default: execute-api)
      --access_key ACCESS_KEY
                            [env var: AWS_ACCESS_KEY_ID] (default: None)
      --secret_key SECRET_KEY
                            [env var: AWS_SECRET_ACCESS_KEY] (default: None)
      --security_token SECURITY_TOKEN
                            [env var: AWS_SECURITY_TOKEN] (default: None)

.. |Build Status| image:: https://travis-ci.org/okigan/awscurl.svg?branch=master
   :target: https://travis-ci.org/okigan/awscurl
