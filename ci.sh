#!/usr/bin/env bash

virtualenv venv -p python2.7

source venv/bin/activate

pip install requirements.txt
pip install requirements-test.txt

pycodestyle -v awscurl
py.test -v