# Feedback task starting environment

Upstream: https://github.com/authlib/joserfc
Upstream commit: `f345ff71cd6c36452a4e11e47b805ad450a95dd8`
Prepared on macOS with CPython 3.12.11. No external database, queue, or cloud account is required.

The dependency file pins the installed runtime and test packages for the selected baseline. It is not a claim that all optional upstream test suites are installed.

From the repository root:

```sh
export NO_INTERNET=1 TZ=UTC UV_NO_CONFIG=1

uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= tests/jwk/test_jwk_set.py tests/jws/test_registry.py tests/jwt/test_claims.py
```

Scope note: The scope is the command below, not all optional upstream integrations.

Observed baseline (2026-11-12): `42 passed, 30 subtests passed in 1.70s`
Whole-command wall time: 2.023 seconds, exit code 0. This is one local measurement, not a runtime guarantee. The first install is excluded.

This seed adds preparation metadata only. Application sources and upstream tests are unchanged; there is no task solution in this commit.
