#!/usr/bin/env bash

python3 -m venv venv

source venv/bin/activate

pip install -r requirements.txt
pip install -r requirements-test.txt

pycodestyle -v awscurl

pytest -v --cov=awscurl --cov-fail-under=77 --cov-report html --cov-report annotate
