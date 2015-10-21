# awscurl
Curl like tool with AWS request signing


## Overview 
Requests to AWS API must be signed (see http://docs.aws.amazon.com/general/latest/gr/signing_aws_api_requests.html) automates
the process of signing and allows to make requests to AWS as simple as standard curl command.


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
