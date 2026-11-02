---
name: local-dev
---

# Local dev — okigan/awscurl

Durable record of the LOCAL-DEV onboarding run (2026-10-09). Follow this to
get from a fresh sandbox snapshot to a fully verified dev environment.

## 1. Prerequisites
- Python 3.10–3.13 on PATH (`python3 --version`). `.python-version` lists the
  exact patch versions CI uses (3.10.16, 3.11.12, 3.12.10, 3.13.3) — any
  3.10–3.13 works for local dev.
- No Docker needed for local dev (Docker exists in the repo for image builds
  and CI-in-docker but is unavailable/unnecessary in the sandbox).
- No external services (no DB, no queue, no cache). Nothing to compose up.
- No secrets required: tests and CI use MOCK credentials
  (`MOCK_AWS_ACCESS_KEY_ID` / `MOCK_AWS_SECRET_ACCESS_KEY` /
  `MOCK_AWS_SESSION_TOKEN`). Never use real AWS credentials for local dev.

## 2. Install
```sh
python3 -m venv venv
. venv/bin/activate
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt -r requirements-test.txt
pip install -e .        # installs the `awscurl` console script
```
(`make venv` does the venv + requirements steps.)

## 3. Verify — the three CI gates
```sh
pycodestyle awscurl          # lint; config in setup.cfg
mypy awscurl/ tests/         # typecheck
AWS_ACCESS_KEY_ID=MOCK_AWS_ACCESS_KEY_ID \
AWS_SECRET_ACCESS_KEY=MOCK_AWS_SECRET_ACCESS_KEY \
AWS_SESSION_TOKEN=MOCK_AWS_SESSION_TOKEN \
pytest --cov=awscurl --cov-fail-under=77
```
Expected on the onboarding run: pycodestyle clean; mypy "no issues found in
12 source files"; 43 passed; coverage 79.43% (gate is 77%).

## 4. Primary user flow (end-to-end signing check)
The app is a CLI, so "start the app" = run `awscurl` itself. The key user flow
is sign-and-send:
1. Start any local HTTP echo server (e.g. `python3 -m http.server` plus a
   tiny handler that dumps request headers).
2. `awscurl --access_key AKIAIOSFODNN7EXAMPLE --secret_key <any> --region us-east-1 --service s3 'http://127.0.0.1:PORT/path?q=1'`
3. Confirm the request arrives with `Authorization: AWS4-HMAC-SHA256
   Credential=AKIAIOSFODNN7EXAMPLE/<date>/us-east-1/s3/aws4_request` and an
   `X-Amz-Date` header. That proves canonical-request → string-to-sign →
   signature → Authorization header, end to end, without hitting AWS.

## 5. Full local CI (optional, slower)
`./scripts/ci.sh` loops over every version in `.python-version` and needs
pyenv; skip it in the sandbox and run the three gates above on the system
Python instead.

## Gotchas
- `awscurl --version` prints usage (there is no version flag) — not a failure.
- Coverage gate (77%) is enforced; keep tests with any source change.
- `pip install -e .` pulls in botocore/boto3/awscrt — first install takes
  a bit; no compilation needed.
- Review priorities from AGENTS.md: SigV4 spec conformance for signing
  functions, never log AWS credentials, curl-style CLI compatibility.
