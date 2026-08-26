# Enterprise AI-SDLC Project

Portable local source snapshot saved on 2026-08-26.

## Contents

```text
implementation/
  PyRIT/                         PyRIT source tree with the evidence producer
  agent-governance-toolkit/
    agent-governance-python/
      agent-sre/                 Agent SRE package and AI-SDLC implementation
    .github/workflows/           Reusable evidence workflow
    tests/ci/                    Workflow contract tests
    docs/                        Operations and package documentation
    examples/enterprise-ai-sdlc/ Runnable offline end-to-end example
demo-output/                     Successful G0-G6 run and signed release artifacts
```

This folder now contains the implementation code itself. Git internals, virtual
environments, caches, build outputs, and unrelated pre-existing AGT files were
intentionally excluded.

## Source state

- Agent Governance Toolkit source commit: `a07d6928cca066ac2cf4dc2b188165d167dd4f1c`
- PyRIT source commit: `ae55de7bb455c36108367c91d2a004a884959d8c`
- The snapshot also includes the uncommitted enterprise AI-SDLC implementation.

Original editable working trees:

- `/Users/kevinburrowes/Documents/vulrn-apps/agent-governance-toolkit`
- `/Users/kevinburrowes/Documents/vulrn-apps/PyRIT`

## Run the included offline example

From this saved project directory, install Agent SRE in a virtual environment:

```bash
cd implementation/agent-governance-toolkit/agent-governance-python/agent-sre
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .
cd ../../../..
PYTHONPATH=implementation/agent-governance-toolkit/agent-governance-python/agent-sre/src \
  python implementation/agent-governance-toolkit/examples/enterprise-ai-sdlc/demo.py \
  --output local-demo-output
```

The example is offline and exits nonzero if any gate, integrity check, or signature
verification fails.

## Saved successful run

`demo-output/` contains:

- canonical change and G0-G6 evidence;
- PyRIT and RAMPART evidence;
- orchestration manifest, approvals, and execution receipt;
- model, routing, cost, and usage SQLite databases; and
- readiness, issued release, and Ed25519 signature artifacts.

Start with `demo-output/summary.json` or
`implementation/agent-governance-toolkit/examples/enterprise-ai-sdlc/README.md`.
