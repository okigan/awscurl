#! /bin/bash
set -o errexit
set -o pipefail
set -o nounset
set -o xtrace

# this script is used to run awscurl from local source -- this would be removed once python modules issue is resolved

python -m awscurl $@
