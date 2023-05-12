venv:
	python3 -m venv venv
	( \
		source venv/bin/activate; \
		pip install --upgrade pip; \
		pip install --upgrade setuptools; \
		pip install -r requirements.txt -r requirements-test.txt; \
	)
