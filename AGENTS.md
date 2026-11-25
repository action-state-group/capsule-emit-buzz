# Agent notes

## Before every push

Run `scripts/check.sh` (about 3 s on an Apple-silicon Mac; needs `uv` and `go`). It runs what CI runs on pull requests and main, except the neutrality term scan, which needs the `NEUTRALITY_TERMS` secret (the scanner's self-test runs).
