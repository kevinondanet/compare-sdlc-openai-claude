# Pilot 1 — docs-only library change

Project class: **documentation-only** (`risk_class: docs_only`). The change package
`changes/CHG-document-shapes-api` adds an API reference for the `shapes` package. Gate
depth profile: G0, G2 (lint/links/doctest) and a light G3 review; no G4/G5.

Walk-through (from this directory, inside a git repository with a commit):

```
aisdlc intake readiness CHG-document-shapes-api
aisdlc plan check CHG-document-shapes-api
aisdlc run change CHG-document-shapes-api --runner dry --yes
aisdlc gate evaluate CHG-document-shapes-api
```
