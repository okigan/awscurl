#!/usr/bin/env bash

virtualenv venv -p python2.7

source venv/bin/activate

pip install -r requirements.txt
pip install -r requirements-test.txt

pycodestyle -v awscurl

pytest -v --cov=awscurl --cov-fail-under=80 --cov-report html --cov-report annotate
