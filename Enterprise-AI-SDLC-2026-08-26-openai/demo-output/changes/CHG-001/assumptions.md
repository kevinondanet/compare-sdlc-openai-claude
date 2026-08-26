# Assumptions and open questions

## Assumptions

- **ASM-001** [validated] The host mediates every send_email call.
  - Validation: pytest tests/test_host_mediation.py

## Open questions

- **QST-001** [answered; owner=messaging-security; blocking=true] Who owns the external-recipient allowlist?
  - Answer: The messaging security team.
