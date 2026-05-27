Audit the supplied FunctionPacket for plausible DeFi/security hypotheses.

Return strict JSON matching FunctionAuditResult:
- function_id
- hypotheses
- candidate_invariants
- rejected_notes

Each hypothesis must include concrete evidence_from_context, an attack_sequence, false_positive_checks, validation_plan, suggested_invariants, rustyfuzz_objective, and conservative confidence_before_validation.

Reject vague issues. Do not call anything a confirmed finding.
