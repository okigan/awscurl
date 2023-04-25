#!/usr/bin/env bash

set -o errexit
set -o pipefail
set -o nounset
set -o xtrace

docker build -t awscurl-ci-ubuntu -f ./ci/ci-ubuntu/Dockerfile .
docker run   -t awscurl-ci-ubuntu bash -c "source /root/venv/bin/activate && cd dd && tox" 

docker build -t awscurl-ci-alpine -f ./ci/ci-alpine/Dockerfile .
docker run   -t awscurl-ci-alpine bash -c "source /root/venv/bin/activate && cd dd && tox" 

docker build -t awscurl-ci-centos -f ./ci/ci-centos/Dockerfile .
docker run   -t awscurl-ci-centos bash -c "source /root/venv/bin/activate && cd dd && tox" 
