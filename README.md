# awscurl
Curl like tool with AWS request signing. [![Build Status](https://travis-ci.org/okigan/awscurl.svg?branch=master)](https://travis-ci.org/okigan/awscurl)


## Overview 
Requests to AWS API must be signed (see [Signing AWS API Requests](http://docs.aws.amazon.com/general/latest/gr/signing_aws_api_requests.html)) 
automates the process of signing and allows to make requests to AWS as simple as standard curl command.


## Installation
  ```sh
  $ pip install awscurl
  ```

## Examples
* Call AWS API Gateway: 
  ```sh
  $ awscurl --service execute-api -X POST -d @request.json  https://<yourhost>.execute-api.us-east-1.amazonaws.com/<your resource>
  ```
  
* Call AWS EC2: 
  ```sh
  $ awscurl --service ec2 -X GET  https://ec2.amazonaws.com?Action=DescribeRegions&Version=2013-10-15
  ```

## Options
```
awscurl --help 
usage: awscurl [-h] [-v] [-X REQUEST] [-d DATA] [-H HEADER] [--region REGION]
               [--service SERVICE] [--access_key ACCESS_KEY]
               [--secret_key SECRET_KEY] [--security_token SECURITY_TOKEN]
               uri

positional arguments:
  uri

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         verbose flag
  -X REQUEST, --request REQUEST
                        Specify request command to use
  -d DATA, --data DATA  HTTP POST data
  -H HEADER, --header HEADER
                        HTTP POST data
  --region REGION       AWS region
  --service SERVICE     AWS service
  --access_key ACCESS_KEY
  --secret_key SECRET_KEY
  --security_token SECURITY_TOKEN

```