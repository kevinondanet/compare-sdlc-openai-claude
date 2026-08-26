# CI artifacts consumed by `aisdlc ci collect-security`

In CI the reusable workflows (`templates/workflows/*.yml`) upload these files and
`collect-security` parses them into `evidence/security.json`. The pilot runs offline, so:

- `ruff.sarif` is **generated at run time** by `run.sh` (`ruff check --output-format sarif`)
  and is the real SAST result for the code in the working copy.
- `dependency-review.json`, `gitleaks.json`, `sbom.spdx.json` and `provenance.intoto.json`
  are **sample artifacts in the exact formats** GitHub dependency review, gitleaks, syft
  and SLSA provenance produce. The application has no third-party dependencies and no
  secrets, so the samples are empty/clean; CI replaces them with the real uploads.
