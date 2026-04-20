# Agents

## Project
This is `awscurl` — a curl-like CLI tool that signs requests with AWS Signature Version 4.

## Key Files to Reference
- `setup.cfg` — code style rules (pycodestyle config)
- `setup.py` — package metadata, dependencies, supported Python versions
- `.github/workflows/pythonapp.yml` — CI checks that must pass (lint + test matrix)
- `requirements-test.txt` — test tooling
- `scripts/ci.sh` — local CI flow

## Build & Test
See `scripts/ci.sh` for the local CI flow and `.github/workflows/pythonapp.yml` for the CI pipeline.

## Review Priorities
- Changes to request signing (`task_1` through `task_4`, `__normalize_query_string`, `aws_url_encode`) must conform to the [AWS SigV4 spec](https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html)
- Never log or expose AWS credentials (access keys, secret keys, tokens) — check `__log`, error paths, and `load_aws_config`
- Maintain backward compatibility of CLI arguments and behavior — see `inner_main` for arg parsing
- CLI arguments should follow curl's style and naming conventions
- Keep dependencies minimal — check `setup.py` for the current set
- New functionality must include unit tests — see `tests/` for existing patterns
