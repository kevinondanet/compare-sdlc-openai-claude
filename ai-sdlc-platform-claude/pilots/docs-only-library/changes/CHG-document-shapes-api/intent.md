---
id: CHG-document-shapes-api
title: Document the shapes API
kernel:
  why: Integrators cannot discover area()/perimeter() without reading the source.
  capabilities:
  - An API reference page for every public function of the shapes package
  - Executable examples so the reference cannot drift from the code
  constraints:
  - Markdown only; no documentation generator is introduced
  - Examples must run with the standard library doctest runner
  non_goals:
  - Changing the behaviour or signatures of the shapes package
  success_signal: docs/api.md documents both functions and doctest passes.
owner: docs-lead
risk_class: docs_only
stakeholders:
- library maintainers
- integrators
labels:
- docs
---
# Intent

Add `docs/api.md`, a reference for `shapes.area` and `shapes.perimeter` with examples that the doctest runner executes.
