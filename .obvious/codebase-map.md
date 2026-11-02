# Codebase map — okigan/awscurl

Single Python CLI package. Depth cap 2.

| Path | Purpose |
|---|---|
| `awscurl/` | The package: `__main__.py` (CLI entry, arg parsing via `inner_main`), `awscurl.py` (SigV4 signing core: task_1–task_4, canonical request, `__normalize_query_string`, `aws_url_encode`, request sending), `utils.py` (small helpers) |
| `tests/` | pytest suite: `stages_test.py` (SigV4 spec conformance per signing stage), `unit_test.py`, `integration_test.py`, `tls_test.py`, `load_aws_config_test.py` (credential loading), `url_parsing_test.py`, `basic_test.py`, `data/` fixtures |
| `scripts/` | `ci.sh` (local CI loop over `.python-version`, needs pyenv), `ci-in-docker.sh`, `install.sh`, `pypi_publish.sh` |
| `ci/` | Dockerfiles for CI images (`ci-alpine`, `ci-amazonlinux`, `ci-centos`, `ci-ubuntu`) |
| `.github/` | Workflows: `pythonapp.yml` (CI: pycodestyle + mypy + pytest matrix), `codeql-analysis.yml`, `dockerhubpublish.yml`, `pythonpublish.yml`; plus dependabot, templates, `copilot-instructions.md` |
| `.vscode/` | Editor launch/debug settings |
| `Makefile` | Targets: `venv` (create venv, install requirements), `docker-build`, `docker-run` |
| `Dockerfile` | Container image for the CLI |
| `setup.py` | Package metadata, console script entry point, `install_requires` |
| `setup.cfg` | pycodestyle config (max-line-length 120, ignores), mypy config |
| `requirements.txt` / `requirements-test.txt` | Runtime and test dependencies |
| `.python-version` | Supported Python versions: 3.10.16, 3.11.12, 3.12.10, 3.13.3 |
| `AGENTS.md` | Agent guidance and review priorities (SigV4 conformance, credential hygiene, curl-style CLI args) |
| `DEVELOP.md` | Docker-based dev run examples |
| `README.md` | User docs: install (pip/brew/docker) and usage examples |
