---
tasks:
- id: TASK-001
  title: Implement health_status with bounded checks
  description: 'service/health.py: run_checks (thread pool, 2 s timeout) and health_status
    returning (200|503, body).'
  requirement_ids:
  - REQ-001
  - REQ-002
  - REQ-003
  depends_on: []
  verification:
    command: python3 -m unittest -q tests.test_health
    expect_exit_code: 0
  status: pending
  files:
  - service/health.py
  - tests/test_health.py
- id: TASK-002
  title: Serve /health from the WSGI application
  description: make_app routes GET /health to health_status and 404s everything else.
  requirement_ids:
  - REQ-001
  - REQ-002
  depends_on: []
  verification:
    command: 'python3 -c "from service.health import make_app; app=make_app({''db'':
      lambda: True}); st=[]; body=b''''.join(app({''PATH_INFO'': ''/health'', ''REQUEST_METHOD'':
      ''GET''}, lambda s,h: st.append(s))); import sys; sys.exit(0 if st and st[0].startswith(''200'')
      and b''\"ok\"'' in body else 1)"'
    expect_exit_code: 0
  status: pending
  files:
  - service/health.py
- id: TASK-003
  title: Document the endpoint contract
  description: 'README: response shape, status codes and the probe interval note.'
  requirement_ids:
  - REQ-001
  depends_on:
  - TASK-001
  - TASK-002
  verification:
    command: python3 -c "import pathlib,sys; sys.exit(0 if '/health' in pathlib.Path('README.md').read_text()
      else 1)"
    expect_exit_code: 0
  status: pending
  files:
  - README.md
---
# Tasks

Tasks are numbered sequentially and each carries an executable verification.
