#!/usr/bin/env bash

set -o errexit
set -o pipefail
set -o nounset
set -o xtrace

images=("ubuntu" "centos")

for image in "${images[@]}"
do
#  echo $image
  docker run -it -v $(pwd):/root "${image}" bash -c "cd && ./install.sh && ./ci.sh"
done
