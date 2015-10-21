# awscurl
Curl like tool with AWS request signing


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
