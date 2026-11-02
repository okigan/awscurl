# obvious.md — okigan/awscurl

## What this repo is
`awscurl` — a curl-like Python CLI that signs HTTP requests with AWS Signature
Version 4 (SigV4) and sends them. Single package, no server, no database, no
external services. Published to PyPI (`pip install awscurl`) and Docker Hub.

## Stack
- Language: Python 3.10–3.13 (see `.python-version`; sandbox has 3.13.x)
- Packaging: setuptools (`setup.py`, `setup.cfg`); console script `awscurl = awscurl.__main__:main`
- Dependencies: `requirements.txt` (requests, configargparse, configparser, botocore);
  `setup.py install_requires` also lists urllib3, boto3, awscrt
- Test tooling: `requirements-test.txt` (pytest, pytest-cov, mock, pycodestyle, mypy, build)
- CI: `.github/workflows/pythonapp.yml` — pycodestyle, mypy, pytest (coverage gate 77%)
  across ubuntu/macOS × Python 3.10–3.13

## Required environment variables
Only for running the CLI/tests without real AWS credentials (CI sets these exact
MOCK values — no real secrets are needed for local dev):
```
AWS_ACCESS_KEY_ID=MOCK_AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY=MOCK_AWS_SECRET_ACCESS_KEY
AWS_SESSION_TOKEN=MOCK_AWS_SESSION_TOKEN
```
`awscurl` also accepts `--access_key` / `--secret_key` / `--region` / `--service`
as CLI flags, which is what the end-to-end signing check uses.

## Commands
```sh
make venv                     # python3 -m venv venv + install requirements*.txt
. venv/bin/activate
pip install -e .              # install the awscurl console script
pycodestyle awscurl           # lint (config in setup.cfg)
mypy awscurl/ tests/          # typecheck
AWS_ACCESS_KEY_ID=MOCK_AWS_ACCESS_KEY_ID \
AWS_SECRET_ACCESS_KEY=MOCK_AWS_SECRET_ACCESS_KEY \
AWS_SESSION_TOKEN=MOCK_AWS_SESSION_TOKEN \
pytest --cov=awscurl --cov-fail-under=77   # tests + 77% coverage gate
./scripts/ci.sh               # full local CI loop over .python-version (needs pyenv)
```
`Dockerfile` builds a runnable image (`make docker-build` / `make docker-run`);
Docker is NOT available in the onboarding sandbox — CI-in-docker
(`scripts/ci-in-docker.sh`) also requires Docker.

## Local verification (run before opening a PR)
1. `pycodestyle awscurl` — exit 0
2. `mypy awscurl/ tests/` — "Success: no issues found"
3. pytest with MOCK AWS_* env vars above — all green, coverage ≥ 77%
4. End-to-end signing: start any local HTTP server, then
   `awscurl --access_key AKIA...EXAMPLE --secret_key ... --region us-east-1 --service s3 http://127.0.0.1:PORT/path?q=1`
   and confirm the request arrives with an `Authorization: AWS4-HMAC-SHA256 Credential=...`
   header and an `X-Amz-Date` header.

## Codebase map
See `codebase-map.md` in this directory.

## Local dev skill
See `skills/local-dev/SKILL.md` in this directory.

## Snapshot
- Snapshot ID: `dg2czim25svou4ylsz87:default`
- Captured: 2026-10-09T23:55:16.450Z (UTC)
- State: fresh checkout with venv at `./venv` (gitignored), deps installed,
  package installed editable, all gates passing

## Notes / gotchas
- `scripts/ci.sh` iterates `.python-version` and requires pyenv; in the sandbox
  use the per-gate commands above on the system Python instead.
- There is no `.env.example`; the MOCK AWS_* values above are the documented
  convention from CI.
- Coverage gate is enforced at 77% (`--cov-fail-under=77`) — current level ~79%.
- Never log or expose AWS credentials in code changes (see `AGENTS.md`).
