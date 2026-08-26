---
summary: Screen both inputs first, then prove it with the safety suite, then the whole portfolio.
waves:
- index: 0
  task_ids:
  - TASK-001
  - TASK-002
  checkpoint: false
  description: Screening of user messages and of tool results (independent).
- index: 1
  task_ids:
  - TASK-003
  checkpoint: false
  description: The RAMPART-style safety suite is green across every category.
- index: 2
  task_ids:
  - TASK-004
  checkpoint: true
  description: Whole suite; human checkpoint before release.
---
# Plan

The red-team baseline runs before wave 0 and again after wave 2; G4 compares the two.
