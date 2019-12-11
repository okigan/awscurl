#!/usr/bin/env bash
set -ex

pip install python-brewer

pybrew \
    -n "Awscurl" \
    -d "Curl like simplicity to access AWS resources with AWS Signature Version 4 request signing." \
    -H https://github.com/okigan/awscurl \
    -g https://github.com/okigan/awscurl.git \
    -r https://github.com/okigan/awscurl/archive/v0.19.tar.gz \
    awscurl \
    awscurl.rb