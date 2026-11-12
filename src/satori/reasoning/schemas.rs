//! Machine-readable output schemas for model-driven Satori stages.
//!
//! These schemas are the single source of truth for the JSON shape a model must
//! emit. They are rendered into prompts and are checked against the Rust types
//! in the tests below, so the prompt and the deserializer cannot drift apart.
//!
//! The previous prompt embedded a prose schema that described
//! `candidate_invariants` as an array of strings and omitted required
//! hypothesis fields (`evidence_from_context`, `required_conditions`,
//! `false_positive_checks`, `validation_plan`, `suggested_invariants`,
//! `rustyfuzz_objective`). Models that followed it produced JSON that
//! `FunctionAuditResult` could not deserialize, which surfaced as
//! "malformed hypothesis JSON" from the Satori pipeline.

pub const FUNCTION_AUDIT_SCHEMA_NAME: &str = "FunctionAuditResult";
pub const RUSTYFUZZ_JOB_SCHEMA_NAME: &str = "RustyFuzzJobSpec";
pub const VALIDATION_VERDICT_SCHEMA_NAME: &str = "ValidationVerdict";

/// JSON Schema for the object `FunctionAuditResult` deserializes from.
///
/// Keep in sync with `crate::satori::types::FunctionAuditResult`;
/// `function_audit_schema_matches_types` enforces that.
pub const FUNCTION_AUDIT_JSON_SCHEMA: &str = r#"{
  "type": "object",
  "additionalProperties": false,
  "required": ["function_id", "hypotheses", "candidate_invariants", "rejected_notes"],
  "properties": {
    "function_id": { "type": "string" },
    "hypotheses": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": [
          "id",
          "title",
          "bug_class",
          "root_cause",
          "affected_contracts",
          "affected_functions",
          "evidence_from_context",
          "required_conditions",
          "attack_sequence",
          "false_positive_checks",
          "validation_plan",
          "suggested_invariants",
          "rustyfuzz_objective",
          "confidence_before_validation"
        ],
        "properties": {
          "id": { "type": "string" },
          "title": { "type": "string" },
          "bug_class": { "type": "string" },
          "root_cause": { "type": "string" },
          "affected_contracts": { "type": "array", "items": { "type": "string" } },
          "affected_functions": { "type": "array", "items": { "type": "string" } },
          "evidence_from_context": { "type": "array", "items": { "type": "string" } },
          "required_conditions": { "type": "array", "items": { "type": "string" } },
          "attack_sequence": {
            "type": "array",
            "items": {
              "type": "object",
              "additionalProperties": false,
              "required": ["actor", "action"],
              "properties": {
                "actor": { "type": "string" },
                "action": { "type": "string" },
                "target": { "type": ["string", "null"] },
                "calldata_hint": { "type": ["string", "null"] },
                "value_hint": { "type": ["string", "null"] }
              }
            }
          },
          "false_positive_checks": { "type": "array", "items": { "type": "string" } },
          "validation_plan": {
            "type": "array",
            "items": {
              "type": "object",
              "additionalProperties": false,
              "required": ["tool", "action", "success_condition"],
              "properties": {
                "tool": { "type": "string" },
                "action": { "type": "string" },
                "success_condition": { "type": "string" }
              }
            }
          },
          "suggested_invariants": {
            "type": "array",
            "items": {
              "type": "object",
              "additionalProperties": false,
              "required": ["id", "description", "check", "expected_signal"],
              "properties": {
                "id": { "type": "string" },
                "description": { "type": "string" },
                "check": { "type": "string" },
                "expected_signal": { "type": "string" }
              }
            }
          },
          "rustyfuzz_objective": { "type": "string" },
          "confidence_before_validation": {
            "type": "number",
            "minimum": 0.0,
            "maximum": 1.0
          }
        }
      }
    },
    "candidate_invariants": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["id", "description", "check", "expected_signal"],
        "properties": {
          "id": { "type": "string" },
          "description": { "type": "string" },
          "check": { "type": "string" },
          "expected_signal": { "type": "string" }
        }
      }
    },
    "rejected_notes": { "type": "array", "items": { "type": "string" } }
  }
}"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::satori::types::{
        AttackStep, CandidateInvariant, FunctionAuditResult, ValidationStep,
        VulnerabilityHypothesis,
    };
    use serde_json::Value;
    use std::collections::BTreeSet;

    fn keys(value: &Value) -> BTreeSet<String> {
        value
            .as_object()
            .expect("expected a JSON object")
            .keys()
            .cloned()
            .collect()
    }

    /// Property names declared by a schema node.
    fn property_keys(schema: &Value) -> BTreeSet<String> {
        keys(&schema["properties"])
    }

    fn required_keys(value: &Value) -> BTreeSet<String> {
        value["required"]
            .as_array()
            .expect("expected a required array")
            .iter()
            .map(|item| item.as_str().expect("required entry").to_string())
            .collect()
    }

    fn sample_audit() -> FunctionAuditResult {
        FunctionAuditResult {
            function_id: "Contract::fn()".to_string(),
            hypotheses: vec![VulnerabilityHypothesis {
                id: "H1".to_string(),
                title: "title".to_string(),
                bug_class: "access-control".to_string(),
                root_cause: "root cause".to_string(),
                affected_contracts: vec!["Contract".to_string()],
                affected_functions: vec!["Contract::fn()".to_string()],
                evidence_from_context: vec!["evidence".to_string()],
                required_conditions: vec!["condition".to_string()],
                attack_sequence: vec![AttackStep {
                    actor: "attacker".to_string(),
                    action: "call".to_string(),
                    target: Some("Contract".to_string()),
                    calldata_hint: Some("0x1234".to_string()),
                    value_hint: None,
                }],
                false_positive_checks: vec!["check".to_string()],
                validation_plan: vec![ValidationStep {
                    tool: "forge".to_string(),
                    action: "test".to_string(),
                    success_condition: "revert".to_string(),
                }],
                suggested_invariants: vec![CandidateInvariant {
                    id: "INV-1".to_string(),
                    description: "description".to_string(),
                    check: "check".to_string(),
                    expected_signal: "signal".to_string(),
                }],
                rustyfuzz_objective: "objective".to_string(),
                confidence_before_validation: 0.5,
            }],
            candidate_invariants: vec![CandidateInvariant {
                id: "INV-1".to_string(),
                description: "description".to_string(),
                check: "check".to_string(),
                expected_signal: "signal".to_string(),
            }],
            rejected_notes: vec!["note".to_string()],
        }
    }

    #[test]
    fn function_audit_schema_is_valid_json() {
        let schema: Value =
            serde_json::from_str(FUNCTION_AUDIT_JSON_SCHEMA).expect("schema must be valid JSON");
        assert_eq!(schema["type"], "object");
    }

    #[test]
    fn function_audit_schema_matches_types() {
        let schema: Value = serde_json::from_str(FUNCTION_AUDIT_JSON_SCHEMA).unwrap();
        let sample = serde_json::to_value(sample_audit()).unwrap();

        // Top-level result object.
        assert_eq!(property_keys(&schema), keys(&sample));
        assert_eq!(required_keys(&schema), keys(&sample));

        // Hypothesis object.
        let hypothesis_schema = &schema["properties"]["hypotheses"]["items"];
        let hypothesis_sample = &sample["hypotheses"][0];
        assert_eq!(property_keys(hypothesis_schema), keys(hypothesis_sample));
        assert_eq!(required_keys(hypothesis_schema), keys(hypothesis_sample));

        // Attack step: the three Option fields are optional, the rest required.
        let attack_schema = &hypothesis_schema["properties"]["attack_sequence"]["items"];
        let attack_sample = &hypothesis_sample["attack_sequence"][0];
        assert_eq!(property_keys(attack_schema), keys(attack_sample));
        assert_eq!(
            required_keys(attack_schema),
            BTreeSet::from(["actor".to_string(), "action".to_string()])
        );

        // Validation step.
        let validation_schema = &hypothesis_schema["properties"]["validation_plan"]["items"];
        let validation_sample = &hypothesis_sample["validation_plan"][0];
        assert_eq!(property_keys(validation_schema), keys(validation_sample));
        assert_eq!(required_keys(validation_schema), keys(validation_sample));

        // Candidate invariant, in both places it appears.
        let invariant_keys = keys(&sample["candidate_invariants"][0]);
        assert_eq!(
            property_keys(&schema["properties"]["candidate_invariants"]["items"]),
            invariant_keys
        );
        assert_eq!(
            required_keys(&schema["properties"]["candidate_invariants"]["items"]),
            invariant_keys
        );
        assert_eq!(
            property_keys(&hypothesis_schema["properties"]["suggested_invariants"]["items"]),
            invariant_keys
        );
    }
}
