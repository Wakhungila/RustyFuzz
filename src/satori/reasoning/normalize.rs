//! Normalizes model-emitted JSON into the exact shape the Rust types expect.
//!
//! Models routinely emit *near*-correct JSON: a hypothesis without
//! `evidence_from_context`, an invariant as a bare string, an attack step as a
//! sentence. Rejecting an entire response for those shapes throws away real
//! analysis and stalls the pipeline, so the shapes are coerced into the
//! canonical form before deserialization.
//!
//! This is a safety net, not a substitute for the prompt schema: coercion
//! never invents analysis, it only reshapes what the model already said. A
//! missing `confidence_before_validation` is coerced to `0.0`, which keeps the
//! hypothesis below any reasonable confidence gate rather than promoting it.

use serde_json::{Map, Value};

/// Coerce a `FunctionAuditResult` payload into the canonical Rust shape.
pub fn normalize_function_audit(value: &mut Value) {
    let Some(root) = value.as_object_mut() else {
        return;
    };

    ensure_string(root, "function_id");

    if !root.get("hypotheses").map(Value::is_array).unwrap_or(false) {
        let hypotheses = root
            .get("hypotheses")
            .cloned()
            .map(|v| vec![v])
            .unwrap_or_default();
        root.insert("hypotheses".to_string(), Value::Array(hypotheses));
    }
    if !root
        .get("candidate_invariants")
        .map(Value::is_array)
        .unwrap_or(false)
    {
        let invariants = root
            .get("candidate_invariants")
            .cloned()
            .map(|v| vec![v])
            .unwrap_or_default();
        root.insert("candidate_invariants".to_string(), Value::Array(invariants));
    }
    ensure_string_array(root, "rejected_notes");

    if let Some(Value::Array(hypotheses)) = root.get_mut("hypotheses") {
        for hypothesis in hypotheses.iter_mut() {
            normalize_hypothesis(hypothesis);
        }
    }
    if let Some(Value::Array(invariants)) = root.get_mut("candidate_invariants") {
        for (index, invariant) in invariants.iter_mut().enumerate() {
            *invariant = coerce_invariant(invariant.clone(), index);
        }
    }
}

fn normalize_hypothesis(value: &mut Value) {
    let Some(hypothesis) = value.as_object_mut() else {
        *value = Value::Object(Map::new());
        return;
    };

    // Legacy alias: some models emit "evidence" for "evidence_from_context".
    if !hypothesis.contains_key("evidence_from_context") {
        if let Some(evidence) = hypothesis.remove("evidence") {
            hypothesis.insert("evidence_from_context".to_string(), evidence);
        }
    }
    // Legacy alias: "mitigations" maps onto the false-positive check list.
    if !hypothesis.contains_key("false_positive_checks") {
        if let Some(mitigations) = hypothesis.remove("mitigations") {
            hypothesis.insert("false_positive_checks".to_string(), mitigations);
        }
    }
    // Legacy alias: bare "confidence".
    if !hypothesis.contains_key("confidence_before_validation") {
        if let Some(confidence) = hypothesis.remove("confidence") {
            hypothesis.insert("confidence_before_validation".to_string(), confidence);
        }
    }

    for key in [
        "affected_contracts",
        "affected_functions",
        "evidence_from_context",
        "required_conditions",
        "false_positive_checks",
    ] {
        ensure_string_array(hypothesis, key);
    }
    ensure_string(hypothesis, "id");
    ensure_string(hypothesis, "title");
    ensure_string(hypothesis, "bug_class");
    ensure_string(hypothesis, "root_cause");
    ensure_string(hypothesis, "rustyfuzz_objective");
    ensure_number(hypothesis, "confidence_before_validation");

    if let Some(Value::Array(steps)) = hypothesis.get_mut("attack_sequence") {
        for step in steps.iter_mut() {
            *step = coerce_attack_step(step.clone());
        }
    } else {
        hypothesis.insert("attack_sequence".to_string(), Value::Array(Vec::new()));
    }

    if let Some(Value::Array(steps)) = hypothesis.get_mut("validation_plan") {
        for step in steps.iter_mut() {
            *step = coerce_validation_step(step.clone());
        }
    } else {
        hypothesis.insert("validation_plan".to_string(), Value::Array(Vec::new()));
    }

    if let Some(Value::Array(invariants)) = hypothesis.get_mut("suggested_invariants") {
        for (index, invariant) in invariants.iter_mut().enumerate() {
            *invariant = coerce_invariant(invariant.clone(), index);
        }
    } else {
        hypothesis.insert("suggested_invariants".to_string(), Value::Array(Vec::new()));
    }
}

fn coerce_invariant(value: Value, index: usize) -> Value {
    let mut map = match value {
        Value::Object(map) => map,
        Value::String(text) => {
            let mut map = Map::new();
            map.insert("description".to_string(), Value::String(text.clone()));
            map.insert("check".to_string(), Value::String(text.clone()));
            map.insert("expected_signal".to_string(), Value::String(text));
            map
        }
        Value::Null => Map::new(),
        other => {
            let mut map = Map::new();
            map.insert("description".to_string(), Value::String(other.to_string()));
            map
        }
    };
    let fallback_id = format!("INV-{}", index + 1);
    if !map
        .get("id")
        .map(|value| value.is_string() && !value.as_str().unwrap_or_default().is_empty())
        .unwrap_or(false)
    {
        map.insert("id".to_string(), Value::String(fallback_id));
    }
    for key in ["description", "check", "expected_signal"] {
        ensure_string(&mut map, key);
    }
    Value::Object(map)
}

fn coerce_attack_step(value: Value) -> Value {
    let mut map = match value {
        Value::Object(map) => map,
        Value::String(text) => {
            let mut map = Map::new();
            map.insert("actor".to_string(), Value::String("model".to_string()));
            map.insert("action".to_string(), Value::String(text));
            map
        }
        Value::Null => Map::new(),
        other => {
            let mut map = Map::new();
            map.insert("action".to_string(), Value::String(other.to_string()));
            map
        }
    };
    ensure_string(&mut map, "actor");
    ensure_string(&mut map, "action");
    for key in ["target", "calldata_hint", "value_hint"] {
        match map.get(key) {
            Some(Value::String(_)) | None => {}
            Some(Value::Null) => {}
            Some(other) => {
                let text = other.to_string();
                map.insert(key.to_string(), Value::String(text));
            }
        }
        if !map.contains_key(key) {
            map.insert(key.to_string(), Value::Null);
        }
    }
    Value::Object(map)
}

fn coerce_validation_step(value: Value) -> Value {
    let mut map = match value {
        Value::Object(map) => map,
        Value::String(text) => {
            let mut map = Map::new();
            map.insert("tool".to_string(), Value::String("model".to_string()));
            map.insert("action".to_string(), Value::String(text.clone()));
            map.insert("success_condition".to_string(), Value::String(text));
            map
        }
        Value::Null => Map::new(),
        other => {
            let mut map = Map::new();
            map.insert("action".to_string(), Value::String(other.to_string()));
            map
        }
    };
    ensure_string(&mut map, "tool");
    ensure_string(&mut map, "action");
    ensure_string(&mut map, "success_condition");
    Value::Object(map)
}

fn ensure_string(map: &mut Map<String, Value>, key: &str) {
    let replacement = match map.get(key) {
        Some(Value::String(_)) => return,
        Some(Value::Null) | None => String::new(),
        Some(other) => other.to_string(),
    };
    map.insert(key.to_string(), Value::String(replacement));
}

fn ensure_string_array(map: &mut Map<String, Value>, key: &str) {
    let replacement = match map.get(key) {
        Some(Value::Array(items)) => Value::Array(
            items
                .iter()
                .map(|item| match item {
                    Value::String(_) => item.clone(),
                    Value::Null => Value::String(String::new()),
                    other => Value::String(other.to_string()),
                })
                .collect(),
        ),
        Some(Value::Null) | None => Value::Array(Vec::new()),
        Some(Value::String(text)) => Value::Array(vec![Value::String(text.clone())]),
        Some(other) => Value::Array(vec![Value::String(other.to_string())]),
    };
    map.insert(key.to_string(), replacement);
}

fn ensure_number(map: &mut Map<String, Value>, key: &str) {
    if map.get(key).map(|value| value.is_number()).unwrap_or(false) {
        return;
    }
    map.insert(
        key.to_string(),
        Value::Number(serde_json::Number::from_f64(0.0).expect("0.0 is representable")),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::satori::reasoning::parser::parse_strict_json;
    use crate::satori::types::FunctionAuditResult;

    fn parse(payload: serde_json::Value) -> FunctionAuditResult {
        let mut payload = payload;
        normalize_function_audit(&mut payload);
        parse_strict_json(&payload.to_string()).expect("normalized payload must deserialize")
    }

    #[test]
    fn coerces_string_invariants_into_objects() {
        let audit = parse(serde_json::json!({
            "function_id": "C::f()",
            "hypotheses": [],
            "candidate_invariants": ["balance must not go negative"],
            "rejected_notes": []
        }));
        assert_eq!(audit.candidate_invariants.len(), 1);
        assert_eq!(audit.candidate_invariants[0].id, "INV-1");
        assert_eq!(
            audit.candidate_invariants[0].description,
            "balance must not go negative"
        );
    }

    #[test]
    fn fills_missing_hypothesis_fields() {
        let audit = parse(serde_json::json!({
            "function_id": "C::f()",
            "hypotheses": [{
                "id": "H1",
                "title": "t",
                "bug_class": "access-control",
                "root_cause": "r",
                "affected_contracts": ["C"],
                "affected_functions": ["C::f()"],
                "evidence": ["line 3"],
                "attack_sequence": ["attacker calls withdraw()"],
                "mitigations": ["owner is a multisig"],
                "confidence": 0.7
            }],
            "candidate_invariants": [],
            "rejected_notes": []
        }));
        let hypothesis = &audit.hypotheses[0];
        assert_eq!(hypothesis.evidence_from_context, vec!["line 3"]);
        assert_eq!(
            hypothesis.false_positive_checks,
            vec!["owner is a multisig"]
        );
        assert_eq!(hypothesis.required_conditions, Vec::<String>::new());
        assert_eq!(hypothesis.confidence_before_validation, 0.7);
        assert_eq!(hypothesis.attack_sequence.len(), 1);
        assert_eq!(
            hypothesis.attack_sequence[0].action,
            "attacker calls withdraw()"
        );
        assert!(hypothesis.attack_sequence[0].target.is_none());
        assert_eq!(hypothesis.validation_plan.len(), 0);
    }

    #[test]
    fn missing_confidence_is_not_promoted() {
        let audit = parse(serde_json::json!({
            "function_id": "C::f()",
            "hypotheses": [{
                "id": "H1",
                "title": "t",
                "bug_class": "access-control",
                "root_cause": "r"
            }],
            "candidate_invariants": [],
            "rejected_notes": []
        }));
        assert_eq!(audit.hypotheses[0].confidence_before_validation, 0.0);
    }

    #[test]
    fn coerces_nested_step_objects() {
        let audit = parse(serde_json::json!({
            "function_id": "C::f()",
            "hypotheses": [{
                "id": "H1",
                "title": "t",
                "bug_class": "access-control",
                "root_cause": "r",
                "attack_sequence": [{"action": "drain", "target": 42}],
                "validation_plan": [{"action": "forge test", "success_condition": "revert"}],
                "suggested_invariants": ["no negative balance"]
            }],
            "candidate_invariants": [],
            "rejected_notes": []
        }));
        let hypothesis = &audit.hypotheses[0];
        assert_eq!(hypothesis.attack_sequence[0].actor, "");
        assert_eq!(hypothesis.attack_sequence[0].target.as_deref(), Some("42"));
        assert_eq!(hypothesis.validation_plan[0].tool, "");
        assert_eq!(hypothesis.validation_plan[0].success_condition, "revert");
        assert_eq!(hypothesis.suggested_invariants[0].id, "INV-1");
    }
}
