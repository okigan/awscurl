#!/usr/bin/env bash

virtualenv venv -p python2.7

source venv/bin/activate

pip install -r requirements.txt
pip install -r requirements-test.txt

pycodestyle -v awscurl

export AWS_ACCESS_KEY_ID=MOCK_AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY=MOCK_AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN=MOCK_AWS_SESSION_TOKEN

pytest -v --cov=awscurl --cov-fail-under=77 --cov-report html --cov-report annotate
