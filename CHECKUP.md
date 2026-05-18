# `awscurl` repository checkup

Branch reviewed: `claude/repo-checkup-review-EPd3L`
HEAD at audit time: `89c74fa` ("Bump version to 0.42 — add README as PyPI long_description")
Audit date: 2026-05-18

This document is read-only: an inventory of vulnerabilities, bugs, risks, and improvements, with file:line references. No source changes are made here. Use it as a menu and pick what to fix next.

## Executive summary

| Severity | Count | Theme |
| --- | --- | --- |
| High | 4 | Committed AWS credentials in tests; credentials logged in `--verbose`; SigV4 header inconsistency for empty security token; unpinned `requirements.txt` |
| Medium | 8 | Parsing bugs (`split("=")`, `split(": ")`); broken `while/break` in `load_aws_config`; deprecated `utcnow()`; `-o` duplicates output; deprecated `setup.py sdist` publish; Docker login via password; duplicate / extra deps in `setup.py`; missing `python_requires` |
| Low | 7+ | Duplicate imports; orphan `pyrightconfig.json`; `__log` uses `pprint`; `boto3` in `install_requires` with no direct use; Dockerfile base images not pinned by digest; missing `MANIFEST.in`; `tls_min/max` validation only triggers when both flags are set |

Current suite status:

- `pycodestyle awscurl` -> 0 issues.
- `mypy awscurl/ tests/` -> 0 issues (`Success: no issues found in 12 source files`).
- Offline `pytest` (unit + stages + url_parsing + load_aws_config + basic) -> 23/23 passing.
- `tests/integration_test.py` and `tests/tls_test.py::TestHTTPSDefaultTLS` require network and live S3 — not exercised here.

---

## 1. Security findings

### 1.1 [HIGH] Real AWS credentials committed in `tests/integration_test.py`

Lines 33-34, 56-57, 79-80, 102-103 contain two base64-encoded strings that decode to a valid AWS Access Key ID (`AKIA…` format, 20 chars) and a 40-character Secret Access Key. The exact strings are in the test file; this document intentionally does not reproduce them to avoid tripping push protection.

Even if these keys are read-only for a public bucket, the pattern is toxic:

- Scanners (GitHub secret scanning, gitleaks, AWS GuardDuty) flag them; base64 evades some but not all.
- Anyone who forks the repo inherits the keys in their history.
- `AGENTS.md` says "Never log or expose AWS credentials" — committing them in source contradicts the project's own directive.

Suggested fix: use `pytest.mark.skipif` when real credentials are not available, and read them from env vars (`AWS_ACCESS_KEY_ID`, etc.) or from a profile; rotate the keys in AWS IAM.

### 1.2 [HIGH] `--verbose` leaks `access_key` / `secret_key` / tokens to stderr

`awscurl/awscurl.py:608-609`:

```python
if args.verbose:
    __log(vars(args))
```

`vars(args)` contains `access_key`, `secret_key`, `security_token`, and `session_token`. `AGENTS.md` explicitly forbids this ("Never log or expose AWS credentials — check `__log`, error paths, and `load_aws_config`"). Reproducible with `awscurl -v --access_key AKIA... ...` — the key shows up in stderr.

Suggested fix: redact before logging (replace the four credential fields with `***` in a copy of `vars(args)`).

### 1.3 [HIGH] `x-amz-security-token` header is sent but NOT signed when token is `""`

`awscurl/awscurl.py:243-244` (`task_1`) uses truthiness:

```python
if security_token:
    canonical_headers_dict['x-amz-security-token'] = security_token
```

`awscurl/awscurl.py:371-372` (`task_4`) uses `is not None`:

```python
if security_token is not None:
    headers['x-amz-security-token'] = security_token
```

With `security_token=""`, the header is sent in the request but is not added to the canonical headers / `signed_headers`. AWS rejects SigV4 requests where an `x-amz-*` header is sent unsigned, so this produces signature mismatches. `tests/unit_test.py::TestMakeRequest::test_make_request` (lines 90-95) freezes the bug as expected behavior (`'x-amz-security-token': ''` appears in the expected dict).

Suggested fix: align both functions on `if security_token:` (or `is not None` with normalization to `None` in `normalize_args`), and update the tests.

### 1.4 [HIGH] `requirements.txt` is not pinned

`requirements.txt` lists `requests`, `configargparse`, `configparser`, `botocore` with no `==` or `>=`. CI pulls "latest" on every run — supply-chain weakness and CI flakiness. `setup.py` has the same problem in `install_requires`.

Suggested fix: pin minimum tested versions (`requests>=2.32,<3`, etc.) and consider `pip-compile` to generate a `requirements.lock`.

### 1.5 [MEDIUM] Docker Hub login uses password (`DOCKER_PASSWORD`)

`.github/workflows/dockerhubpublish.yml:14`. Docker Hub recommends **access tokens** (`DOCKER_TOKEN`) with restricted scope; a password grants full account access.

### 1.6 [MEDIUM] PyPI publish uses user / password (`TWINE_USERNAME` / `TWINE_PASSWORD`)

`.github/workflows/pythonpublish.yml:21-22`. PyPI now requires 2FA — switch to **trusted publishing (OIDC)** or at minimum `TWINE_USERNAME=__token__` plus a project-scoped API token.

### 1.7 [MEDIUM] `_TLSAdapter` disables hostname and CN verification when `--insecure`

`awscurl/awscurl.py:430-432` — intentional behavior (matches curl `-k`). It is important that `--insecure` remains opt-in and never becomes a default; the current code does that correctly. Worth a note, not a fix.

### 1.8 [LOW] Dockerfile does not pin the base image digest

`Dockerfile:2` / `:19`: `python:3-alpine`. Reproducible and tamper-resistant builds require a digest pin like `python:3.13.3-alpine@sha256:...`. Same applies to `ci/ci-*/Dockerfile`.

### 1.9 [LOW] CI Dockerfiles install pyenv via `curl | bash`

`ci/ci-*/Dockerfile`: `RUN curl https://pyenv.run | bash`. Runs unauthenticated remote code during CI build — supply-chain risk. Not in the hot path (manual CI only), but worth noting.

---

## 2. Functional bugs

### 2.1 [MEDIUM] `__normalize_query_string` drops parts of values containing `=`

`awscurl/awscurl.py:384-391`:

```python
parameter_pairs = (list(map(str.strip, s.split("=")))
                   for s in query.split('&') if len(s) > 0)
normalized = '&'.join('%s=%s' % (aws_url_encode(p[0]), aws_url_encode(p[1]) if len(p) > 1 else '')
                      for p in sorted(parameter_pairs))
```

For `?token=abc=def`, `split("=")` returns `['token','abc','def']`; only `p[0]` and `p[1]` are used, so the result becomes `token=abc`, losing `=def`. Fix: `s.split("=", 1)`. The `str.strip` on values is also suspect — SigV4 does not require stripping query values, and stripping breaks values that legitimately start or end with whitespace (rare, but worth removing).

### 2.2 [MEDIUM] `load_aws_config` stops at the first missing field

`awscurl/awscurl.py:480-494`:

```python
while True:
    if access_key is None and config.has_option(profile, "aws_access_key_id"):
        access_key = config.get(profile, "aws_access_key_id")
    else:
        break
    if secret_key is None and config.has_option(profile, "aws_secret_access_key"):
        ...
```

If the caller passes `access_key` but not `secret_key`, the first condition falls into the `else: break` and `secret_key` is never read from the file. The `while True` is an "if in disguise" and the short-circuit logic is inverted. Rewrite without the loop, reading each field independently.

### 2.3 [MEDIUM] Parsing a header with more than one `": "` raises `ValueError`

`awscurl/awscurl.py:623`:

```python
headers = {k: v for (k, v) in map(lambda s: s.split(": "), args.header)}
```

`-H "Authorization: Bearer foo: bar"` — `split(": ")` returns 3 items, so the dict comprehension fails with `ValueError: too many values to unpack`. Use `s.split(": ", 1)`.

### 2.4 [MEDIUM] `-o` / `--output` always duplicates output to stdout

`awscurl/awscurl.py:660-669`: `print(response.text)` runs unconditionally; `args.output` only writes the file afterwards. curl's `-o file` redirects — it does not duplicate. Today the body lands both on stdout and in the file.

### 2.5 [MEDIUM] `--data-binary` controls the write mode of `--output`

`awscurl/awscurl.py:663-669`: the file write mode (`"wb"` vs `"w"`) depends on `args.data_binary`, but `data_binary` is a **request** flag, not a **response** flag. A user who sends JSON and receives binary ends up with a corrupted file. The decision should come from something like `--output-binary`, or always use `"wb"` with `response.content`.

### 2.6 [MEDIUM] `make_request` always calls `datetime.utcnow()` (deprecated)

`awscurl/awscurl.py:407-408`:

```python
def __now():
    return datetime.datetime.utcnow()
```

`utcnow()` is deprecated on Python 3.12+ (returns naive datetime). Replace with `datetime.datetime.now(datetime.timezone.utc)`. It still works today but emits `DeprecationWarning` and will eventually be removed. CI already runs 3.13 (`.python-version`).

### 2.7 [MEDIUM] `--tls-min` / `--tls-max` only validate order when both are supplied

`awscurl/awscurl.py:448-452`: `if tls_min is not None and tls_max is not None`. A user who passes only `--tls-min 1.3` on a system whose `maximum_version` is 1.2 gets an opaque handshake failure. A simple check against the supported limits would help.

### 2.8 [MEDIUM] `--access_key` / `--secret_key` / `--security_token` / `--session_token` break curl's naming convention

The README and `AGENTS.md` say to "follow curl's style and naming conventions". The rest of the flags use hyphens (`--data-binary`, `--fail-with-body`, `--tls-min`), but these four use underscores. Adding aliases (`--access-key` next to `--access_key`) via `dest=` would fix this without breaking backwards compatibility.

### 2.9 [LOW] Redundant `import urllib` + `from urllib.parse import quote`

`awscurl/awscurl.py:21-22`. `urllib.parse.urlparse` is already used on line 230; collapse into `from urllib.parse import urlparse, quote`.

### 2.10 [LOW] Duplicate `from typing import Dict`

`awscurl/awscurl.py:7` and `:20`. mypy accepts it, pycodestyle does not flag it, but it is noise.

### 2.11 [LOW] `url_path_to_dict` rolls its own regex instead of `urllib.parse.urlparse`

`awscurl/awscurl.py:54-75`. The regex is fragile (the comment admits it was copied from StackOverflow). `urlparse` covers every case the tests assert; the existing tests would still pass after the refactor.

### 2.12 [LOW] The "optional" `botocore` import is dead code

`awscurl/awscurl.py:509-519`: `try: import botocore` inside a `try/except ImportError`, but `botocore` is already a top-level import on line 18. The happy path is always taken; the `except ImportError` is unreachable.

### 2.13 [LOW] `credentials_path` is built with `+ "/.aws/credentials"`

`awscurl/awscurl.py:626`. Breaks on Windows; use `os.path.join(os.path.expanduser("~"), ".aws", "credentials")` or `pathlib.Path.home() / ".aws" / "credentials"`.

---

## 3. Dependencies / packaging

### 3.1 [MEDIUM] `setup.py:36` lists `configparser` (Py2 backport) — redundant on Py3

`configparser` has been part of the standard library since Python 3.0. Listing it forces users to download a useless package.

### 3.2 [MEDIUM] `setup.py:39` lists `boto3` in `install_requires` with no direct use

The code imports `botocore` only (`from botocore import crt, awsrequest` etc.). `boto3` drags in `s3transfer` and other heavy dependencies (~10 MB extra). Remove it.

### 3.3 [MEDIUM] `setup.py` is missing `python_requires`

CI exercises Py 3.10 / 3.11 / 3.12 / 3.13, but the package allows `pip install` on any version. The `dict[str, str]` type hint in `tests/unit_test.py:77` breaks on <3.9. Add `python_requires=">=3.10"`.

### 3.4 [LOW] No `MANIFEST.in` despite `setup.py` reading `README.md` for `long_description`

`setup.py:9-10` calls `open("README.md")` at build time. Modern setuptools includes `README.md` in the sdist by default, but it is fragile; adding `MANIFEST.in` with `include README.md LICENSE` makes the sdist install robust.

### 3.5 [LOW] Publish workflow still uses `python setup.py sdist bdist_wheel`

`scripts/pypi_publish.sh:5` and `.github/workflows/pythonpublish.yml:23`. setuptools deprecated the direct invocation; use `python -m build`.

### 3.6 [LOW] `pyrightconfig.json` is orphaned

The file exists but no CI step runs pyright (only `mypy`). Either start using it (replace `mypy` with `pyright` in `pythonapp.yml`) or remove the file.

---

## 4. CI / CD

### 4.1 Redundant matrix

`pythonapp.yml` runs `ubuntu-22.04`, `ubuntu-24.04`, and `ubuntu-latest` in parallel. `ubuntu-latest` currently resolves to `24.04` (it will become `26.04` at some point). Keeping `ubuntu-22.04` plus `ubuntu-latest` already covers the useful cases.

### 4.2 No pip cache

No step uses `actions/setup-python` with `cache: pip`. Each job downloads dependencies from scratch (4 OS jobs * 4 Python versions = 16 installs). Adding `cache: pip` saves CI minutes.

### 4.3 `--cov-fail-under=77` is low

The coverage gate is 77%. Worth investigating where the gap is (likely `load_aws_config` and error branches) and raising it incrementally.

### 4.4 Workflows do not set minimum `permissions:`

No workflow YAML defines `permissions:` — every run inherits the repo default. Good practice is `permissions: contents: read` at the top of each workflow and elevating per job (for example `packages: write` only where the image is published).

### 4.5 No dedicated Dockerfile lint job

`hadolint` would help. The current `Dockerfile` has `pip install --user botocore` in the builder stage (line 11) that is redundant with the `pip install /app-source-dir` on line 15.

---

## 5. Documentation / governance

- `README.md` lists CLI options in a hand-curated "Options" section; it is already out of date (it does not mention `--tls-min` / `--tls-max`). Generating it from argparse (e.g. via `argparse-manpage`) would prevent drift.
- `DEVELOP.md` has 11 lines; local venv instructions are hidden inside the `Makefile`. Worth merging.
- `.github/PULL_REQUEST_TEMPLATE.md` was not audited here, but worth checking whether it requests a test checklist.
- There is no `SECURITY.md` telling reporters how to disclose CVEs — add one.
- There is no `CHANGELOG.md`; release notes live only on GitHub.

---

## 6. Prioritized list (for choosing what to attack first)

1. **Remove AWS keys from tests** (section 1.1) — isolated change in `tests/integration_test.py`, requires rotation in AWS.
2. **Stop logging credentials in `--verbose`** (section 1.2) — roughly 5-line patch in `inner_main`.
3. **Fix the inconsistent `x-amz-security-token` logic** (section 1.3) — affects SigV4 with empty token; tests need to be adjusted.
4. **Pin minimum dependency versions in `requirements.txt` and `setup.py`** (sections 1.4, 3.1, 3.2, 3.3).
5. **Parsing fixes** (sections 2.1, 2.3) — subtle bugs that hit real payloads.
6. **`load_aws_config` while/break inversion** (section 2.2).
7. **`-o` behavior** (sections 2.4, 2.5).
8. **`utcnow()` deprecation** (section 2.6).
9. **CI permissions / cache / matrix** (section 4.x).
10. **Cleanup / refactor** (sections 2.9-2.13, 3.5, 3.6).

---

## 7. How this checkup was produced

- Full reads of: `awscurl/{awscurl.py,utils.py,__main__.py,__init__.py}`, `setup.py`, `setup.cfg`, `requirements*.txt`, `Dockerfile`, `Makefile`, `scripts/*`, `tests/*`, `.github/workflows/*`, `.github/{dependabot.yml,CODEOWNERS,copilot-instructions.md}`, `ci/*/Dockerfile`.
- `pycodestyle -v awscurl` -> 0 issues.
- `mypy awscurl/ tests/` -> 0 issues.
- Offline `pytest` (excluding `integration_test.py` and `tls_test.py::TestHTTPSDefaultTLS`) -> 23 passed.
- Out-of-tree decoding of the base64 strings in `integration_test.py` to confirm that the bytes form a valid AWS access key + secret pair (the values themselves are not reproduced here).
- `git log --oneline -20` for baseline and recent PR history (#235, #232-#234).
