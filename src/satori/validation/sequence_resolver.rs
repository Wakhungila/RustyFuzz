//! Resolves model-written attack steps into executable transactions.
//!
//! Models describe attacks in prose ("call approve(spender, new_amount)") and
//! name generic actors ("attacker"). The validation runner deliberately refuses
//! to execute anything that is not an explicit transaction — actor address,
//! hex calldata, target — so prose alone can never become a live campaign.
//!
//! This module bridges that gap deterministically and locally: it looks the
//! mentioned function up in the statically analysed function set, derives its
//! 4-byte selector, encodes default arguments for the declared parameter
//! types, and binds a fixed attacker address. A step that cannot be resolved
//! is *not* guessed at — the whole sequence stays unresolved and the job keeps
//! its "needs more context" verdict, so the runner never runs a campaign it
//! cannot explain.
//!
//! The resolved transaction is a fuzzing *seed*, not a proof: arguments are
//! type-correct defaults that the mutator then perturbs. Only an oracle hit
//! can promote anything to an artifact.

use crate::satori::types::{AttackStep, FunctionSummary};
use revm::primitives::{Address, U256};
use std::str::FromStr;

/// Deterministic account used when a hypothesis names only a role
/// ("attacker", "malicious_implementation") instead of a concrete address.
pub fn default_attacker() -> Address {
    let mut bytes = [0u8; 20];
    bytes[16..].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    Address::from(bytes)
}

/// Everything the resolver needs to turn prose into transactions.
pub struct ResolverContext<'a> {
    /// Contract the hypothesis targets.
    pub target: Address,
    /// Functions found by static analysis, with their selectors.
    pub functions: &'a [FunctionSummary],
    /// Account bound to steps that name a role instead of an address.
    pub attacker: Address,
}

/// Resolves every step of an attack sequence.
///
/// Returns `None` when any step cannot be resolved: the caller must then keep
/// the sequence untouched so validation reports the missing context instead of
/// running something the analyst cannot account for.
pub fn resolve_attack_sequence(
    steps: &[AttackStep],
    context: &ResolverContext<'_>,
) -> Option<Vec<AttackStep>> {
    if steps.is_empty() {
        return None;
    }
    let mut resolved = Vec::with_capacity(steps.len());
    for step in steps {
        resolved.push(resolve_step(step, context)?);
    }
    Some(resolved)
}

fn resolve_step(step: &AttackStep, context: &ResolverContext<'_>) -> Option<AttackStep> {
    let actor = resolve_address(&step.actor).unwrap_or(context.attacker);
    let target = resolve_address(step.target.as_deref().unwrap_or_default())
        .unwrap_or(context.target);
    let calldata = resolve_calldata(step, context)?;
    let value = step
        .value_hint
        .as_deref()
        .and_then(|value| parse_value(value))
        .unwrap_or(U256::ZERO);
    Some(AttackStep {
        actor: format!("{actor}"),
        action: step.action.clone(),
        target: Some(format!("{target}")),
        calldata_hint: Some(calldata),
        value_hint: Some(format!("{value}")),
    })
}

/// Parses an address, or extracts the first address embedded in free text.
fn resolve_address(text: &str) -> Option<Address> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(address) = Address::from_str(trimmed) {
        return Some(address);
    }
    // "attacker 0x1234...5678" still names a concrete account.
    let mut candidate = String::new();
    for (index, character) in trimmed.char_indices() {
        if character == 'x' && trimmed[..index].ends_with('0') {
            candidate.clear();
            candidate.push('0');
            candidate.push('x');
            continue;
        }
        if !candidate.is_empty() {
            if character.is_ascii_hexdigit() {
                candidate.push(character);
            } else {
                break;
            }
        }
        if candidate.len() == 42 {
            break;
        }
    }
    if candidate.len() == 42 {
        return Address::from_str(&candidate).ok();
    }
    None
}

/// Builds the calldata for a step: explicit hex when the model supplied it,
/// otherwise the selector of the function the step names.
fn resolve_calldata(step: &AttackStep, context: &ResolverContext<'_>) -> Option<String> {
    if let Some(hint) = step.calldata_hint.as_deref() {
        if let Some(calldata) = normalize_calldata(hint) {
            return Some(calldata);
        }
    }
    let function = match_function(&step.action, context.functions)?;
    let selector = function.selector.as_deref()?;
    let types = parameter_types(&function.signature);
    let arguments = encode_default_arguments(&types, context.attacker)?;
    let mut calldata = hex::decode(selector.trim_start_matches("0x")).ok()?;
    calldata.extend_from_slice(&arguments);
    Some(format!("0x{}", hex::encode(calldata)))
}

/// Accepts only concrete hex payloads of at least one selector word.
fn normalize_calldata(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let hex_part = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X"))?;
    if hex_part.len() < 8 || hex_part.len() % 2 != 0 {
        return None;
    }
    if !hex_part.chars().all(|character| character.is_ascii_hexdigit()) {
        return None;
    }
    Some(format!("0x{}", hex_part.to_ascii_lowercase()))
}

/// Finds the function a step refers to.
///
/// The step text wins; when it names no known function the hypothesis'
/// affected-function list is consulted by the caller through
/// `resolve_attack_sequence_with_hints`.
fn match_function<'a>(
    action: &str,
    functions: &'a [FunctionSummary],
) -> Option<&'a FunctionSummary> {
    let lowered = action.to_ascii_lowercase();
    let mut best: Option<&FunctionSummary> = None;
    for function in functions {
        if function.selector.is_none() {
            continue;
        }
        let name = function.name.to_ascii_lowercase();
        if name.is_empty() {
            continue;
        }
        if !mentions_function(&lowered, &name) {
            continue;
        }
        let better = match best {
            None => true,
            Some(current) => name.len() > current.name.len(),
        };
        if better {
            best = Some(function);
        }
    }
    best
}

/// Whether the action text refers to the function by name.
fn mentions_function(action: &str, name: &str) -> bool {
    let mut start = 0usize;
    while let Some(index) = action[start..].find(name) {
        let absolute = start + index;
        let before = action[..absolute]
            .chars()
            .next_back()
            .map(|character| !character.is_ascii_alphanumeric() && character != '_')
            .unwrap_or(true);
        let after = action[absolute + name.len()..]
            .chars()
            .next()
            .map(|character| !character.is_ascii_alphanumeric() && character != '_')
            .unwrap_or(true);
        if before && after {
            return true;
        }
        start = absolute + name.len();
    }
    false
}

/// ABI parameter types of a canonical signature.
fn parameter_types(signature: &str) -> Vec<String> {
    let Some(open) = signature.find('(') else {
        return Vec::new();
    };
    let Some(close) = signature.rfind(')') else {
        return Vec::new();
    };
    if close <= open {
        return Vec::new();
    }
    split_top_level(&signature[open + 1..close], ',')
}

/// Splits on `separator`, ignoring separators nested in parentheses.
fn split_top_level(text: &str, separator: char) -> Vec<String> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut current = String::new();
    for character in text.chars() {
        match character {
            '(' => {
                depth += 1;
                current.push(character);
            }
            ')' => {
                depth -= 1;
                current.push(character);
            }
            _ if character == separator && depth == 0 => {
                if !current.trim().is_empty() {
                    parts.push(current.trim().to_string());
                }
                current = String::new();
            }
            _ => current.push(character),
        }
    }
    if !current.trim().is_empty() {
        parts.push(current.trim().to_string());
    }
    parts
}

/// Encodes type-correct default arguments for a parameter list.
fn encode_default_arguments(types: &[String], attacker: Address) -> Option<Vec<u8>> {
    let mut heads: Vec<Vec<u8>> = Vec::with_capacity(types.len());
    let mut tails: Vec<Vec<u8>> = Vec::new();
    let head_slots = types
        .iter()
        .map(|kind| if is_dynamic_kind(kind) { 1usize } else { 1usize })
        .sum::<usize>();

    let mut tail_cursor = head_slots;
    for kind in types {
        match classify_kind(kind, attacker)? {
            AbiKind::Static(word) => heads.push(word),
            AbiKind::Dynamic(tail) => {
                heads.push(offset_word(tail_cursor));
                tail_cursor += tail.len() / 32;
                tails.push(tail);
            }
        }
    }

    let mut out = Vec::new();
    for head in heads {
        out.extend_from_slice(&head);
    }
    for tail in tails {
        out.extend_from_slice(&tail);
    }
    Some(out)
}

/// Whether a type is dynamically encoded (offset + tail).
fn is_dynamic_kind(type_text: &str) -> bool {
    matches!(
        classify_kind(type_text, default_attacker()),
        Some(AbiKind::Dynamic(_))
    )
}

enum AbiKind {
    /// A single 32-byte head word.
    Static(Vec<u8>),
    /// A tail encoding appended after all head words.
    Dynamic(Vec<u8>),
}

fn classify_kind(type_text: &str, attacker: Address) -> Option<AbiKind> {
    let kind = type_text.trim();
    if kind.is_empty() {
        return Some(AbiKind::Static(word_from_u256(U256::ZERO)));
    }
    if kind == "bool" {
        return Some(AbiKind::Static(word_from_u256(U256::ZERO)));
    }
    if kind == "address" {
        return Some(AbiKind::Static(word_from_address(attacker)));
    }
    if kind.starts_with("uint") || kind.starts_with("int") {
        // A zero-valued integer argument is a degenerate no-op that most
        // contracts reject outright (`require(amount > 0)`), so the seed
        // reverts before the oracle ever sees the call. One is the smallest
        // value that still exercises the path; the mutator perturbs it from
        // there.
        return Some(AbiKind::Static(word_from_u256(U256::from(1))));
    }
    if kind == "bytes" || kind == "string" {
        return Some(AbiKind::Dynamic(word_from_u256(U256::ZERO)));
    }
    if kind.starts_with("bytes") && kind.len() > 5 {
        // bytes1..bytes32 are static, right-padded to 32 bytes.
        return Some(AbiKind::Static(vec![0u8; 32]));
    }
    if kind.ends_with("[]") {
        // Dynamic arrays: a zero-length array is a length word of zero.
        return Some(AbiKind::Dynamic(word_from_u256(U256::ZERO)));
    }
    if kind.starts_with('(') {
        let inner = kind.trim_start_matches('(').trim_end_matches(')');
        let types = split_top_level(inner, ',');
        let encoded = encode_default_arguments(&types, attacker)?;
        return Some(AbiKind::Dynamic(encoded));
    }
    // Contract, interface and enum types are address- or integer-shaped in the
    // ABI; treating them as an address keeps the seed call well-formed.
    if kind
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || character == '_')
    {
        return Some(AbiKind::Static(word_from_address(attacker)));
    }
    None
}

fn word_from_u256(value: U256) -> Vec<u8> {
    value.to_be_bytes::<32>().to_vec()
}

fn word_from_address(address: Address) -> Vec<u8> {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(address.as_slice());
    word.to_vec()
}

fn offset_word(slots: usize) -> Vec<u8> {
    word_from_u256(U256::from(slots as u64) * U256::from(32u64))
}

fn parse_value(value: &str) -> Option<U256> {
    let trimmed = value.trim();
    if let Some(hex_value) = trimmed.strip_prefix("0x") {
        U256::from_str_radix(hex_value, 16).ok()
    } else {
        U256::from_str_radix(trimmed, 10).ok()
    }
}

/// The ERC20 balance observation the proof ladder requires before the mint.
///
/// The ladder proves a mint violation by showing the recipient's balance
/// *increased*, so it needs the balance as it stood before the privileged
/// call. Without that observation the replay can show the mint happened but
/// not that it changed anything, and the finding stays a heuristic.
pub const ERC20_BALANCE_OF_SIGNATURE: &str = "balanceOf(address)";

/// Views whose return value states whether an account may perform a
/// privileged action.
///
/// These are the only views the protocol oracle can read a *denial* from: the
/// mint-authorization rule needs to see the policy refuse the caller before
/// the privileged call succeeds, and `owner()` can only ever say
/// "authorized", never "denied".
pub const AUTHORIZATION_POLICY_SIGNATURES: &[&str] = &["canMint(address)", "isMinter(address)"];

/// Builds the probe step that asks the target what its policy says about the
/// actor.
///
/// The probe is bound to the same account as the privileged call, because the
/// oracle compares the policy's address argument against the caller of that
/// call.
pub fn authorization_probe_step(
    policy: &FunctionSummary,
    caller: Address,
    context: &ResolverContext<'_>,
) -> Option<AttackStep> {
    let selector = policy.selector.as_deref()?;
    let mut calldata = hex::decode(selector.trim_start_matches("0x")).ok()?;
    if parameter_types(&policy.signature)
        .iter()
        .any(|kind| kind == "address")
    {
        calldata.extend_from_slice(&word_from_address(caller));
    }
    Some(AttackStep {
        actor: format!("{caller}"),
        action: format!(
            "call {} to establish the authorization precondition",
            policy.signature
        ),
        target: Some(format!("{}", context.target)),
        calldata_hint: Some(format!("0x{}", hex::encode(calldata))),
        value_hint: Some("0".to_string()),
    })
}

/// Builds the probe that records the recipient's balance around the mint.
pub fn balance_probe_step(
    balance_of: &FunctionSummary,
    recipient: Address,
    caller: Address,
    purpose: &str,
    context: &ResolverContext<'_>,
) -> Option<AttackStep> {
    let selector = balance_of.selector.as_deref()?;
    let mut calldata = hex::decode(selector.trim_start_matches("0x")).ok()?;
    calldata.extend_from_slice(&word_from_address(recipient));
    Some(AttackStep {
        actor: format!("{caller}"),
        action: format!("call {} to {purpose}", balance_of.signature),
        target: Some(format!("{}", context.target)),
        calldata_hint: Some(format!("0x{}", hex::encode(calldata))),
        value_hint: Some("0".to_string()),
    })
}

/// Extracts the recipient a mint call pays out to.
pub fn mint_recipient(step: &AttackStep) -> Option<Address> {
    let hint = step.calldata_hint.as_deref()?;
    let bytes = hex::decode(hint.trim_start_matches("0x")).ok()?;
    if bytes.len() != 68 || bytes[..4] != [0x40, 0xc1, 0x0f, 0x19] {
        return None;
    }
    Some(Address::from_slice(&bytes[16..36]))
}

/// The account a resolved step runs as.
pub fn step_caller(step: &AttackStep) -> Option<Address> {
    Address::from_str(step.actor.trim()).ok()
}

/// Finds the policy view that a hypothesis' stated preconditions refer to.
///
/// The hypothesis is the analyst's own statement of what must hold before the
/// attack works ("attacker is not an authorized minter"). Establishing that
/// precondition is what turns "the privileged path ignores the policy" into
/// an observable violation, so the campaign asks the contract directly
/// instead of assuming the precondition held.
pub fn policy_probe_for_preconditions<'a>(
    preconditions: &[String],
    functions: &'a [FunctionSummary],
) -> Option<&'a FunctionSummary> {
    let text = preconditions.join(" ").to_ascii_lowercase();
    if text.is_empty() {
        return None;
    }
    functions.iter().find(|function| {
        AUTHORIZATION_POLICY_SIGNATURES.contains(&function.signature.as_str())
            && mentions_function(&text, &function.name.to_ascii_lowercase())
    })
}

/// Whether a step performs a mint, the privileged action the protocol oracle
/// understands.
pub fn is_mint_action(action: &str) -> bool {
    action.to_ascii_lowercase().contains("mint")
}

/// Resolves an attack sequence, falling back to the hypothesis' affected
/// function names when the step text names no known function.
pub fn resolve_attack_sequence_with_hints(
    steps: &[AttackStep],
    affected_functions: &[String],
    context: &ResolverContext<'_>,
) -> Option<Vec<AttackStep>> {
    if let Some(resolved) = resolve_attack_sequence(steps, context) {
        return Some(resolved);
    }
    // Retry each step using the affected-function names as the selector hint.
    let mut resolved = Vec::with_capacity(steps.len());
    for step in steps {
        let mut candidate = step.clone();
        if candidate.calldata_hint.is_none()
            || candidate
                .calldata_hint
                .as_deref()
                .and_then(normalize_calldata)
                .is_none()
        {
            let function = affected_functions
                .iter()
                .find_map(|name| {
                    context.functions.iter().find(|function| {
                        function.name.eq_ignore_ascii_case(name.trim())
                            && function.selector.is_some()
                    })
                })?;
            let selector = function.selector.as_deref()?;
            let types = parameter_types(&function.signature);
            let arguments = encode_default_arguments(&types, context.attacker)?;
            let mut calldata = hex::decode(selector.trim_start_matches("0x")).ok()?;
            calldata.extend_from_slice(&arguments);
            candidate.calldata_hint = Some(format!("0x{}", hex::encode(calldata)));
        }
        resolved.push(resolve_step(&candidate, context)?);
    }
    Some(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn function(name: &str, signature: &str, selector: &str) -> FunctionSummary {
        FunctionSummary {
            id: format!("Vault::{signature}"),
            contract: "Vault".to_string(),
            name: name.to_string(),
            signature: signature.to_string(),
            selector: Some(selector.to_string()),
            file: std::path::PathBuf::from("Vault.sol"),
            visibility: "external".to_string(),
            mutability: "nonpayable".to_string(),
            modifiers: Vec::new(),
            source_snippet: String::new(),
            reads: Vec::new(),
            writes: Vec::new(),
            internal_calls: Vec::new(),
            external_calls: Vec::new(),
            detector_signals: Vec::new(),
            criticality_score: 0.5,
        }
    }

    fn context() -> ResolverContext<'static> {
        // Leaked deliberately: the context borrows a slice built in the test.
        let functions = Box::leak(Box::new(vec![
            function("approve", "approve(address,uint256)", "0x095ea7b3"),
            function("withdraw", "withdraw(uint256)", "0x2e1a7d4d"),
            function("addCollateral", "addCollateral(address,uint256)", "0x1c7a4fff"),
        ]));
        ResolverContext {
            target: Address::from_str("0x00000000000000000000000000000000000000aa").unwrap(),
            functions,
            attacker: default_attacker(),
        }
    }

    #[test]
    fn prose_step_becomes_an_executable_transaction() {
        let steps = vec![AttackStep {
            actor: "attacker".to_string(),
            action: "attacker calls approve(spender, new_amount)".to_string(),
            target: None,
            calldata_hint: None,
            value_hint: None,
        }];
        let resolved = resolve_attack_sequence(&steps, &context()).expect("must resolve");
        assert_eq!(resolved.len(), 1);
        assert_eq!(
            Address::from_str(&resolved[0].actor).unwrap(),
            default_attacker()
        );
        assert_eq!(
            Address::from_str(resolved[0].target.as_deref().unwrap()).unwrap(),
            Address::from_str("0x00000000000000000000000000000000000000aa").unwrap()
        );
        let calldata = resolved[0].calldata_hint.as_deref().unwrap();
        assert!(calldata.starts_with("0x095ea7b3"), "{calldata}");
        // selector (4 bytes) + two 32-byte words
        assert_eq!(calldata.len(), 2 + 8 + 128);
    }

    #[test]
    fn explicit_calldata_is_preserved() {
        let steps = vec![AttackStep {
            actor: "0x00000000000000000000000000000000000000bb".to_string(),
            action: "call withdraw".to_string(),
            target: Some("0x00000000000000000000000000000000000000cc".to_string()),
            calldata_hint: Some("0x2e1a7d4d00000000000000000000000000000000000000000000000000000001".to_string()),
            value_hint: None,
        }];
        let resolved = resolve_attack_sequence(&steps, &context()).expect("must resolve");
        assert_eq!(
            resolved[0].calldata_hint.as_deref(),
            Some("0x2e1a7d4d00000000000000000000000000000000000000000000000000000001")
        );
        assert_eq!(
            resolved[0].actor,
            "0x00000000000000000000000000000000000000bb"
        );
    }

    #[test]
    fn unresolvable_function_is_not_guessed() {
        let steps = vec![AttackStep {
            actor: "attacker".to_string(),
            action: "attacker exploits a hypothetical backdoor".to_string(),
            target: None,
            calldata_hint: None,
            value_hint: None,
        }];
        assert!(resolve_attack_sequence(&steps, &context()).is_none());
    }

    #[test]
    fn affected_functions_act_as_a_fallback_hint() {
        let steps = vec![AttackStep {
            actor: "attacker".to_string(),
            action: "manipulate the position".to_string(),
            target: None,
            calldata_hint: None,
            value_hint: None,
        }];
        let hints = vec!["withdraw".to_string()];
        let resolved =
            resolve_attack_sequence_with_hints(&steps, &hints, &context()).expect("must resolve");
        assert!(resolved[0]
            .calldata_hint
            .as_deref()
            .unwrap()
            .starts_with("0x2e1a7d4d"));
    }

    #[test]
    fn dynamic_parameters_encode_a_zero_length_tail() {
        let functions = Box::leak(Box::new(vec![function(
            "submit",
            "submit(bytes,uint256)",
            "0xaaaaaaaa",
        )]));
        let context = ResolverContext {
            target: Address::from_str("0x00000000000000000000000000000000000000aa").unwrap(),
            functions,
            attacker: default_attacker(),
        };
        let steps = vec![AttackStep {
            actor: "attacker".to_string(),
            action: "call submit(payload, amount)".to_string(),
            target: None,
            calldata_hint: None,
            value_hint: None,
        }];
        let resolved = resolve_attack_sequence(&steps, &context).expect("must resolve");
        let calldata = resolved[0].calldata_hint.as_deref().unwrap();
        assert!(calldata.starts_with("0xaaaaaaaa"), "{calldata}");
        // selector + 2 head words + 1 tail word = 100 bytes
        assert_eq!(calldata.len(), 2 + 200);
        // The first head word is the dynamic offset (0x40 = two head words).
        assert_eq!(&calldata[10..74], &format!("{:064x}", 0x40));
        // The tail is a zero-length payload.
        assert_eq!(&calldata[calldata.len() - 64..], &"0".repeat(64));
    }
}
