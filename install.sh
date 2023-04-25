#!/bin/env bash

set -o errexit
set -o pipefail
set -o nounset
set -o xtrace


OS_RELEASE=$(. /etc/os-release; echo "${NAME}")

if [ "${OS_RELEASE}" = "Ubuntu" ]; then
    apt update
    apt install -y sudo
    echo 'tzdata tzdata/Areas select Europe' | debconf-set-selections
    echo 'tzdata tzdata/Zones/Europe select Paris' | debconf-set-selections
    DEBIAN_FRONTEND="noninteractive" apt install -y tzdata

    apt install -y curl git \
    build-essential \
    autoconf \
    automake \
    libtool \
    libffi-dev libreadline-dev libz-dev libsqlite-dev libssl-dev \
    libreadline-dev libsqlite3-dev wget curl libncurses5-dev libncursesw5-dev \
    xz-utils tk-dev libffi-dev libbz2-dev liblzma-dev git
elif [ "${OS_RELEASE}" = "CentOS Linux" ]; then
    yum update -y
    yum group install -y "Development Tools"
    yum install -y libffi-devel readline-devel zlib-devel bzip2-devel sqlite-devel openssl-devel git
fi

curl -L https://github.com/pyenv/pyenv-installer/raw/master/bin/pyenv-installer | bash
export PATH="/root/.pyenv/bin:$PATH"
if [ -z "${PROMPT_COMMAND:-}" ]; then
  export PROMPT_COMMAND=""
fi
eval "$(pyenv init -)"
eval "$(pyenv virtualenv-init -)"

grep -v '^ *#' < .python-version | while IFS= read -r line
do
  pyenv install -s "${line}"
done
pip install tox
