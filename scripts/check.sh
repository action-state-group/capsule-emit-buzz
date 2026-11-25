#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Local check run before every push: the commands the pull_request and main CI jobs run.
# Needs uv and go on PATH. Not run here: the neutrality term scan, which needs the
# NEUTRALITY_TERMS secret; the scanner's self-test runs.
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONDONTWRITEBYTECODE=1

# neutrality.yml
python3 .github/neutrality_scan.py --self-test
# tests.yml: python
uv run --isolated --no-project --python 3.12 --with '.[dev]' python -m pytest -q -p no:cacheprovider
# tests.yml: go
(cd parity/go && go test ./...)
