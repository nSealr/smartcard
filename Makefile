.PHONY: setup test lint audit docs ci

PYTHON := .venv/bin/python
PIP := $(PYTHON) -m pip

setup:
	python3 -m venv .venv
	$(PIP) install --disable-pip-version-check -r requirements.txt
	$(PIP) install --disable-pip-version-check .

test:
	$(PYTHON) scripts/verify_repo.py
	$(PYTHON) -m unittest discover -s tests

lint:
	$(PYTHON) scripts/verify_repo.py
	$(PYTHON) -m compileall -q tools tests

audit:
	$(PYTHON) scripts/verify_repo.py
	$(PIP) check

docs:
	$(PYTHON) scripts/verify_repo.py

ci: setup test lint audit docs
