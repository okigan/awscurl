## Some useful commands for local development
### Build docker image
```sh

docker build -t awscurl .

docker run --rm -ti -v "$HOME/.aws:/root/.aws" -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_SECURITY_TOKEN -e AWS_PROFILE -e AWS_REGION awscurl  "${api_url_base}/api/rxxxxx"

docker run -it --entrypoint sh awscurl 
```
