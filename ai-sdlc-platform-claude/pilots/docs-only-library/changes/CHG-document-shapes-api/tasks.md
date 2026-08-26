---
tasks:
- id: TASK-001
  title: Write docs/api.md with a section per public function
  description: 'Document area() and perimeter(): signature, arguments, return, errors.'
  requirement_ids:
  - REQ-001
  depends_on: []
  verification:
    command: python3 -c "import pathlib,sys; t=pathlib.Path('docs/api.md').read_text();
      sys.exit(0 if '## shapes.area' in t and '## shapes.perimeter' in t else 1)"
    expect_exit_code: 0
  status: pending
  files:
  - docs/api.md
- id: TASK-002
  title: Make every example executable
  description: Turn the examples into doctest blocks and run them.
  requirement_ids:
  - REQ-002
  depends_on:
  - TASK-001
  verification:
    command: python3 -m doctest docs/api.md
    expect_exit_code: 0
  status: pending
  files:
  - docs/api.md
---
# Tasks

Tasks are numbered sequentially and each carries an executable verification.
