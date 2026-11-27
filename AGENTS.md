# Agent notes

## Before every push

Run `scripts/check.sh` (about 6 s on an Apple-silicon Mac; needs `uv` and `go`). CI's `tests` workflow runs this same script on pull requests and main. The one CI check it does not run is the neutrality term scan, which needs the `NEUTRALITY_TERMS` secret (the scanner's self-test runs).
