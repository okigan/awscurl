#!/bin/bash
set -e

pip install twine

python setup.py sdist bdist_wheel

twine upload dist/*