#!/usr/bin/env bash

set -o errexit
set -o pipefail
set -o nounset
set -o xtrace

docker_run() {
    local image_type=$1
    local script_file=$2
    echo building "${image_type}" image -- first time it could take a few minutes
    docker build -t awscurl-ci-"$image_type" -f ./ci/ci-"$image_type"/Dockerfile . && \
    docker run -t awscurl-ci-"$image_type" bash -c "$script_file"
}

docker_run "ubuntu" "./scripts/ci.sh"
docker_run "alpine" "./scripts/ci.sh"
docker_run "centos" "./scripts/ci.sh"
