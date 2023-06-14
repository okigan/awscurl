venv/bin/python:
	python3 -m venv venv
	( \
		. ./venv/bin/activate; \
		which python; \
		pip install --upgrade pip; \
		pip install --upgrade setuptools; \
		pip install -r requirements.txt -r requirements-test.txt; \
	)

venv: venv/bin/python

PYTHON_VERSIONS := $(shell cat .python-version)

.PHONY: install_python_versions

install_python_versions:
	@for version in $(PYTHON_VERSIONS); do \
		echo "Installing Python version $$version"; \
		pyenv install $$version; \
	done
