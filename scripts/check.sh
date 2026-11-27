#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Local check run before every push. CI's tests.yml runs this same script on pull requests and main.
# Needs uv and go on PATH. Not run here: the neutrality term scan, which needs the
# NEUTRALITY_TERMS secret; the scanner's self-test runs.
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONDONTWRITEBYTECODE=1

# neutrality scanner self-test (the term scan itself is neutrality.yml's)
python3 .github/neutrality_scan.py --self-test
# Python reference implementation and tests
uv run --isolated --no-project --python 3.12 --with '.[dev]' python -m pytest -q -p no:cacheprovider
# Go parity harness
(cd parity/go && go test ./...)
