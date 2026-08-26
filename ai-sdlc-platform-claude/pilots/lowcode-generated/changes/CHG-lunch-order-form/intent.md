---
id: CHG-lunch-order-form
title: Lunch order form
kernel:
  why: 'Every Friday someone walks around with a paper sheet collecting lunch orders
    and then retypes them into an email for the caterer. Today: Orders get lost, quantities
    are misread and the office manager retypes 40 orders every week.'
  capabilities:
  - Team members can submit a lunch order in a form in under one minute
  - The office manager can see all orders in a table
  - The office manager can export the table as CSV
  constraints:
  - Standard-library Python only
  - the Friday 10:00 cut-off is fixed
  - the caterer menu has at most 10 dishes
  non_goals:
  - Payments and expense claims
  - Menu management by the caterer
  success_signal: Lunch-related emails to the office manager drop from 20 to under
    5 per week within two months of launch
owner: office-manager@example.com
risk_class: standard
stakeholders:
- Team member
- Office manager
created_at: '2026-08-26T06:10:42.999337Z'
labels:
- discovery
---
# Lunch order form

**Change:** CHG-lunch-order-form  
**Owner:** (unassigned)  
**Risk class:** standard

## 1. Problem statement

Every Friday someone walks around with a paper sheet collecting lunch orders and then retypes them into an email for the caterer.

## 2. Users and personas

| Persona | Needs |
| --- | --- |
| Team member | order my lunch without hunting for the paper sheet |
| Office manager | see every order in one table and send it to the caterer |

## 3. Current pain

Orders get lost, quantities are misread and the office manager retypes 40 orders every week.

## 4. Desired outcomes (capabilities)

- Team members can submit a lunch order in a form quickly
- The office manager can see some orders in a table
- The office manager can export the table as TBD

## 5. Out of scope (non-goals)

- Payments and expense claims
- Menu management by the caterer

## 6. Must never

- Accept an order after the Friday cut-off

## 7. Success measure

Fewer lunch-related emails

## 8. Constraints

- (none stated)

## 9. Data sensitivity

No personal data - dish names, quantities and team names only

## 10. Integrations

- (none stated)

## 11. Draft requirements

| ID | Kind | Priority | Requirement |
| --- | --- | --- | --- |
| REQ-001 | functional | must | The system SHALL allow team members to submit a lunch order in a form quickly |
| REQ-002 | functional | must | The system SHALL allow the office manager to see some orders in a table |
| REQ-003 | functional | must | The system SHALL allow the office manager to export the table as TBD |
| REQ-004 | functional | must | The system SHALL NOT accept an order after the Friday cut-off |

## 12. Assumptions

- The primary users are: Team member; Office manager.
- No personal or otherwise sensitive data is processed by this change.

## 13. Open questions

- OQ-001: The success measure 'Fewer lunch-related emails' has no number: what is the target value and when is it measured?
- OQ-002 (blocking): Who is the accountable owner of this change?
- OQ-003: (constraints) Any hard constraints: deadlines, budget, technology that must or must not be used, regulations?
- OQ-004: (integrations) Which other systems, services or teams does this need to talk to or depend on?
