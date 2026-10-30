//! Symbol binding: mapping a predicate symbol to storage locations (§4.4).
//!
//! This is the layer that cannot be derived from an ABI alone, and the layer where
//! silence causes wrong answers. Two rules shape it:
//!
//! 1. **The bit range is mandatory.** Solidity packs small values into one 256-bit
//!    slot, so `bool initialized` at offset 0 and `address owner` at offset 96 share
//!    a slot. Reading the whole slot for both produces garbage that looks plausible.
//!    A manifest that omits `offset_bits`/`width_bits` is **refused at load**, not at
//!    evaluation (owner ruling, §9 item 5), because a predicate that only breaks
//!    mid-campaign wastes the run.
//!
//! 2. **Mappings cannot be enumerated.** Keys must be supplied explicitly, and the
//!    binder reports how many of them it could actually observe (§9 item 4).

use crate::{Int256, Symbol};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::collections::BTreeMap;
use std::fmt;

/// Width of one EVM storage slot in bits.
pub const SLOT_BITS: u16 = 256;

/// Largest address span in bits, used to sanity-check `address` bindings.
const ADDRESS_BITS: u16 = 160;

/// Errors raised while loading or validating a binding manifest.
///
/// All of these are **load-time** failures. Nothing here can surface mid-campaign.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BindingError {
    /// The exact wording is fixed by the owner ruling (§9 item 5) so that the
    /// message is greppable and unambiguous.
    #[error("binding {symbol}: offset_bits/width_bits required (no default)")]
    BitRangeRequired { symbol: String },
    #[error("binding {symbol}: width_bits must be 1..=256, got {width}")]
    WidthOutOfRange { symbol: String, width: u16 },
    #[error(
        "binding {symbol}: offset_bits + width_bits exceeds 256 (offset {offset}, width {width})"
    )]
    BitRangeOverflow {
        symbol: String,
        offset: u16,
        width: u16,
    },
    #[error("binding {symbol}: unknown kind `{kind}`; expected `slot` or `mapping`")]
    UnknownKind { symbol: String, kind: String },
    #[error("binding {symbol}: mapping requires at least one key")]
    EmptyKeySet { symbol: String },
    #[error("binding {symbol}: key `{key}` is not a valid {key_type}")]
    BadKey {
        symbol: String,
        key: String,
        key_type: &'static str,
    },
    #[error("binding {symbol}: address key type requires a 20-byte address")]
    AddressKeyRequired { symbol: String },
    #[error("manifest has no target address")]
    MissingTarget,
    #[error("invalid hex in {field}: {value}")]
    BadHex { field: &'static str, value: String },
    #[error("invalid manifest JSON: {0}")]
    Json(String),
    #[error("predicate references `{symbol}`, which the manifest does not bind")]
    UnboundSymbol { symbol: String },
}

/// What a symbol denotes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingKind {
    /// A single storage slot, possibly a sub-range of it.
    Slot,
    /// A mapping rooted at `base_slot`, with an explicit key set.
    Mapping,
    /// The return word of a pure/view function call.
    ///
    /// Exists because a whole class of real properties is a statement about a
    /// function's *answer* rather than about stored state: a proof verifier's
    /// invariant is "this forged proof does not verify", which lives in a return
    /// value. Without this kind such a property is inexpressible.
    ReturnValue,
}

/// A resolved storage location for one symbol.
///
/// `offset_bits` counts from the **least-significant** end of the slot, matching
/// Solidity's packing order: in `contract C { bool b; address a; }` the bool sits at
/// offset 0 width 8 and the address at offset 96 width 160 within slot 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    /// Contract holding the storage. For a delegatecall proxy this is the storage
    /// context, not the implementation address; attribution is decided upstream.
    /// Contract that owns the storage, or is called for a `return_value` binding.
    pub address: [u8; 20],
    pub kind: BindingKind,
    pub slot: [u8; 32],
    /// Bit offset within the slot. Mandatory; never defaulted.
    pub offset_bits: u16,
    /// Bit width. Mandatory; never defaulted.
    pub width_bits: u16,
    /// Explicit key set for a mapping, in declaration order. Empty for a plain slot.
    pub keys: Vec<[u8; 32]>,
    /// Zero-based index of the return word to read, for a `return_value` binding.
    ///
    /// `getReserves()` on the Basin Well returns `uint256[]`; a predicate reads one
    /// element at a time, so the binding names which. Zero for every other kind.
    pub word_index: u16,
}

impl Binding {
    pub fn address_hex(&self) -> String {
        format!("0x{}", hex(&self.address))
    }

    /// Slot for a plain binding, or the derived slot for one mapping key.
    ///
    /// Mapping derivation follows Solidity: `keccak256(h(k) . p)` where `h` left-pads
    /// the key to 32 bytes and `p` is the base slot as a 32-byte word.
    pub fn slot_for_key(&self, key: &[u8; 32]) -> [u8; 32] {
        match self.kind {
            BindingKind::Slot | BindingKind::ReturnValue => self.slot,
            BindingKind::Mapping => mapping_slot(key, &self.slot),
        }
    }

    /// True when the symbol denotes a mapping over several slots.
    pub fn is_mapping(&self) -> bool {
        matches!(self.kind, BindingKind::Mapping)
    }

    /// Number of keys the manifest declared for a mapping.
    pub fn declared_key_count(&self) -> usize {
        self.keys.len()
    }

    /// True when the symbol is a function's return word rather than storage.
    pub fn is_return_value(&self) -> bool {
        matches!(self.kind, BindingKind::ReturnValue)
    }
}

/// `keccak256(key_word || base_slot)` — the Solidity mapping slot formula.
pub fn mapping_slot(key: &[u8; 32], base_slot: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(key);
    hasher.update(base_slot);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Extracts `width_bits` bits starting at `offset_bits` (LSB-first) from a slot word.
///
/// Returns `None` when the range is out of bounds, which the loader already rejects;
/// the `Option` exists so this cannot silently read past the word.
pub fn extract_bits(word: &[u8; 32], offset_bits: u16, width_bits: u16) -> Option<Int256> {
    if width_bits == 0 || width_bits > SLOT_BITS {
        return None;
    }
    if u32::from(offset_bits) + u32::from(width_bits) > u32::from(SLOT_BITS) {
        return None;
    }
    // Big-endian word: bit 0 is byte 31, bit 255 is byte 0 bit 7.
    let mut value = Int256::ZERO;
    for bit in 0..width_bits {
        let source_bit = u32::from(offset_bits) + u32::from(bit);
        let byte_index = 31 - (source_bit / 8) as usize;
        let bit_index = source_bit % 8;
        if (word[byte_index] >> bit_index) & 1 == 1 {
            // Place it at `bit` in the result, again LSB-first.
            let target_byte = 31 - (u32::from(bit) / 8) as usize;
            let target_bit = (u32::from(bit) % 8) as u8;
            let mut bytes = *value.as_bytes();
            bytes[target_byte] |= 1 << target_bit;
            value = Int256(bytes);
        }
    }
    Some(value)
}

/// Loads a manifest written as JSON, refusing anything ambiguous.
///
/// The raw JSON shape is deliberately close to the design doc's example so a reader
/// can compare them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindingManifest {
    pub target: String,
    pub symbols: BTreeMap<String, RawBinding>,
}

/// One symbol as written in a manifest. Every field is optional **in the JSON type**
/// only so a missing bit range can produce the required error message instead of a
/// generic serde failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawBinding {
    pub kind: String,
    /// Slot for `slot` kind; base slot for `mapping`.
    /// Storage slot for `slot`/`mapping`; absent for `return_value`.
    #[serde(default)]
    pub slot: Option<String>,
    #[serde(default)]
    pub offset_bits: Option<u16>,
    #[serde(default)]
    pub width_bits: Option<u16>,
    #[serde(default)]
    pub keys: Vec<String>,
    #[serde(default)]
    pub key_type: Option<String>,
    /// Overrides `target` for a `return_value` binding: the contract actually called.
    ///
    /// Needed because a property often reads a *dependent* contract: the Basin
    /// invariant `balanceOf(well) >= reserves[0]` calls the token, not the Well.
    #[serde(default)]
    pub call_target: Option<String>,
    /// Which return word to read when the function returns several.
    #[serde(default)]
    pub word_index: Option<u16>,
}

impl BindingManifest {
    pub fn from_json(text: &str) -> Result<Self, BindingError> {
        serde_json::from_str(text).map_err(|e| BindingError::Json(e.to_string()))
    }

    /// Validates every binding and resolves it into the runtime form.
    ///
    /// Fails on the **first** problem, in symbol order, so the message is stable
    /// across runs and can be asserted in a test.
    pub fn resolve(&self) -> Result<BTreeMap<String, Binding>, BindingError> {
        let address = parse_address(&self.target)?;
        let mut resolved = BTreeMap::new();
        for (symbol, raw) in &self.symbols {
            resolved.insert(symbol.clone(), resolve_one(symbol, raw, address)?);
        }
        Ok(resolved)
    }

    /// Resolves and additionally checks that the predicate's symbols are all bound.
    pub fn resolve_for(
        &self,
        required: &[Symbol],
    ) -> Result<BTreeMap<String, Binding>, BindingError> {
        let resolved = self.resolve()?;
        for symbol in required {
            let root = symbol.root().to_string();
            if !resolved.contains_key(&root) && !resolved.contains_key(&symbol.to_string()) {
                return Err(BindingError::UnboundSymbol {
                    symbol: symbol.to_string(),
                });
            }
        }
        Ok(resolved)
    }
}

fn resolve_one(symbol: &str, raw: &RawBinding, address: [u8; 20]) -> Result<Binding, BindingError> {
    // The bit range is checked first: it is the one field whose absence produces a
    // silently wrong answer rather than a loud failure.
    let (Some(offset_bits), Some(width_bits)) = (raw.offset_bits, raw.width_bits) else {
        return Err(BindingError::BitRangeRequired {
            symbol: symbol.to_string(),
        });
    };
    if width_bits == 0 || width_bits > SLOT_BITS {
        return Err(BindingError::WidthOutOfRange {
            symbol: symbol.to_string(),
            width: width_bits,
        });
    }
    if u32::from(offset_bits) + u32::from(width_bits) > u32::from(SLOT_BITS) {
        return Err(BindingError::BitRangeOverflow {
            symbol: symbol.to_string(),
            offset: offset_bits,
            width: width_bits,
        });
    }

    let kind = match raw.kind.as_str() {
        "slot" => BindingKind::Slot,
        "mapping" => BindingKind::Mapping,
        "return_value" => BindingKind::ReturnValue,
        other => {
            return Err(BindingError::UnknownKind {
                symbol: symbol.to_string(),
                kind: other.to_string(),
            })
        }
    };

    // A return-value binding names an ABI-encoded word, not a storage slot, so it
    // carries the selector for identification and a zero slot placeholder.
    let slot = if matches!(kind, BindingKind::ReturnValue) {
        match raw.slot.as_deref() {
            Some(text) if !text.trim().is_empty() => parse_word("slot", text)?,
            _ => [0u8; 32],
        }
    } else {
        let text = raw.slot.as_deref().ok_or_else(|| BindingError::BadHex {
            field: "slot",
            value: String::new(),
        })?;
        parse_word("slot", text)?
    };

    let keys = if matches!(kind, BindingKind::Mapping) {
        if raw.keys.is_empty() {
            return Err(BindingError::EmptyKeySet {
                symbol: symbol.to_string(),
            });
        }
        let key_type = raw.key_type.as_deref().unwrap_or("address");
        let mut parsed = Vec::with_capacity(raw.keys.len());
        for key in &raw.keys {
            parsed.push(parse_key(symbol, key, key_type)?);
        }
        parsed
    } else {
        Vec::new()
    };

    // A `return_value` binding may name a different contract to call, which is how a
    // property reads a dependent contract (a token's `balanceOf`) rather than the
    // target itself.
    let call_address = match raw.call_target.as_deref() {
        Some(text) => parse_address(text)?,
        None => address,
    };

    Ok(Binding {
        address: call_address,
        kind,
        slot,
        offset_bits,
        width_bits,
        keys,
        word_index: raw.word_index.unwrap_or(0),
    })
}

fn parse_key(symbol: &str, key: &str, key_type: &str) -> Result<[u8; 32], BindingError> {
    let trimmed = key.trim();
    match key_type {
        "address" => {
            let bytes = parse_fixed_hex(trimmed, 20).ok_or_else(|| BindingError::BadKey {
                symbol: symbol.to_string(),
                key: key.to_string(),
                key_type: "address",
            })?;
            // parse_fixed_hex right-aligns into a 32-byte word already, which is
            // exactly the ABI encoding of an address key.
            Ok(bytes)
        }
        // uint256 and bytes32 keys are already slot-width.
        "uint256" | "bytes32" => parse_fixed_hex(trimmed, 32).ok_or_else(|| BindingError::BadKey {
            symbol: symbol.to_string(),
            key: key.to_string(),
            key_type: if key_type == "uint256" {
                "uint256"
            } else {
                "bytes32"
            },
        }),
        other => Err(BindingError::UnknownKind {
            symbol: symbol.to_string(),
            kind: format!("key_type {other}"),
        }),
    }
}

fn parse_address(text: &str) -> Result<[u8; 20], BindingError> {
    let word = parse_fixed_hex(text.trim(), 20).ok_or(BindingError::MissingTarget)?;
    let mut address = [0u8; 20];
    address.copy_from_slice(&word[12..]);
    Ok(address)
}

fn parse_word(field: &'static str, text: &str) -> Result<[u8; 32], BindingError> {
    // Slots are often written as a short hex quantity (`0x3`), so left-pad.
    let trimmed = text.trim();
    let hex = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if hex.len() > 64 || hex.is_empty() || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(BindingError::BadHex {
            field,
            value: trimmed.to_string(),
        });
    }
    let padded = format!("{hex:0>64}");
    let mut out = [0u8; 32];
    for (index, chunk) in padded.as_bytes().chunks(2).enumerate() {
        let pair = std::str::from_utf8(chunk).expect("ascii");
        out[index] = u8::from_str_radix(pair, 16).expect("validated hex");
    }
    Ok(out)
}

/// Parses exactly `width` bytes of hex, right-aligned into a 32-byte word.
///
/// An address is 20 bytes and must be written as exactly 40 hex digits: a shorter
/// string is ambiguous (is `0x1` the first byte or the last?), so it is rejected
/// rather than guessed. The result is right-aligned because that is the ABI
/// encoding of an address or uint key.
fn parse_fixed_hex(text: &str, width: usize) -> Option<[u8; 32]> {
    let hex = text.strip_prefix("0x").unwrap_or(text);
    if hex.len() != width * 2 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    let offset = 32 - width;
    for (index, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let pair = std::str::from_utf8(chunk).ok()?;
        out[offset + index] = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(out)
}

pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

impl fmt::Display for Binding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}[slot 0x{} bits {}..{}]",
            self.address_hex(),
            hex(&self.slot),
            self.offset_bits,
            self.offset_bits + self.width_bits
        )
    }
}

/// Convenience: the address-width check used by tests and by future validation.
pub fn is_address_width(width_bits: u16) -> bool {
    width_bits == ADDRESS_BITS
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Symbol;

    fn manifest(json: &str) -> BindingManifest {
        BindingManifest::from_json(json).expect("manifest must parse")
    }

    // ---- §9 item 5: bit range is mandatory and refused at load --------

    #[test]
    fn refuses_a_binding_with_no_bit_range_using_the_exact_message() {
        let m = manifest(
            r#"{
                "target": "0x00000000000000000000000000000000000000aa",
                "symbols": {
                    "totalSupply": { "kind": "slot", "slot": "0x3" }
                }
            }"#,
        );
        let error = m.resolve().unwrap_err();
        assert_eq!(
            error.to_string(),
            "binding totalSupply: offset_bits/width_bits required (no default)"
        );
    }

    #[test]
    fn refuses_a_partial_bit_range() {
        // Supplying only one of the two is the same class of ambiguity.
        let m = manifest(
            r#"{
                "target": "0x00000000000000000000000000000000000000aa",
                "symbols": {
                    "x": { "kind": "slot", "slot": "0x1", "width_bits": 256 }
                }
            }"#,
        );
        assert!(matches!(
            m.resolve().unwrap_err(),
            BindingError::BitRangeRequired { .. }
        ));
    }

    #[test]
    fn refuses_a_bit_range_that_leaves_the_slot() {
        let m = manifest(
            r#"{
                "target": "0x00000000000000000000000000000000000000aa",
                "symbols": {
                    "x": { "kind": "slot", "slot": "0x1",
                           "offset_bits": 200, "width_bits": 100 }
                }
            }"#,
        );
        assert!(matches!(
            m.resolve().unwrap_err(),
            BindingError::BitRangeOverflow { .. }
        ));
    }

    #[test]
    fn refuses_zero_width() {
        let m = manifest(
            r#"{
                "target": "0x00000000000000000000000000000000000000aa",
                "symbols": {
                    "x": { "kind": "slot", "slot": "0x1",
                           "offset_bits": 0, "width_bits": 0 }
                }
            }"#,
        );
        assert!(matches!(
            m.resolve().unwrap_err(),
            BindingError::WidthOutOfRange { .. }
        ));
    }

    #[test]
    fn refuses_an_unknown_kind() {
        let m = manifest(
            r#"{
                "target": "0x00000000000000000000000000000000000000aa",
                "symbols": {
                    "x": { "kind": "array", "slot": "0x1",
                           "offset_bits": 0, "width_bits": 256 }
                }
            }"#,
        );
        assert!(matches!(
            m.resolve().unwrap_err(),
            BindingError::UnknownKind { .. }
        ));
    }

    // ---- happy path ---------------------------------------------------

    #[test]
    fn resolves_a_plain_slot() {
        let m = manifest(
            r#"{
                "target": "0x00000000000000000000000000000000000000aa",
                "symbols": {
                    "totalSupply": { "kind": "slot", "slot": "0x3",
                                     "offset_bits": 0, "width_bits": 256 }
                }
            }"#,
        );
        let resolved = m.resolve().expect("must resolve");
        let binding = &resolved["totalSupply"];
        assert_eq!(binding.offset_bits, 0);
        assert_eq!(binding.width_bits, 256);
        assert_eq!(binding.declared_key_count(), 0);
        assert!(!binding.is_mapping());
    }

    // ---- §4.4: packed slots, the failure this whole gate exists for ----

    #[test]
    fn extracts_a_packed_bool_and_address_from_one_slot() {
        // `contract C { bool initialized; uint96 gap; address owner; }` in slot 0:
        // initialized at bit 0 width 8, owner at bit 96 width 160 (Solidity order).
        let owner = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff, 0x01, 0x02, 0x03, 0x04, 0x05,
        ];
        let mut slot = [0u8; 32];
        // owner lives in the high 20 bytes (offset 96 = 12 bytes from the top).
        slot[0..20].copy_from_slice(&owner);
        slot[31] = 1; // initialized = true

        let initialized = extract_bits(&slot, 0, 8).expect("in range");
        assert_eq!(initialized, Int256::from_u64(1));

        let extracted_owner = extract_bits(&slot, 96, 160).expect("in range");
        let mut expected = [0u8; 32];
        expected[12..].copy_from_slice(&owner);
        assert_eq!(extracted_owner, Int256(expected));
    }

    #[test]
    fn reading_the_whole_slot_would_conflate_two_fields() {
        // This is the bug the mandatory bit range prevents: a full-slot read of a
        // packed bool returns the address too.
        let mut slot = [0u8; 32];
        slot[0..20].copy_from_slice(&[0xab; 20]);
        slot[31] = 1;
        let whole = extract_bits(&slot, 0, 256).expect("in range");
        assert_ne!(whole, Int256::from_u64(1));
        assert_ne!(whole, Int256::ZERO);
    }

    #[test]
    fn rejects_an_out_of_range_extraction() {
        let slot = [0u8; 32];
        assert!(extract_bits(&slot, 250, 16).is_none());
        assert!(extract_bits(&slot, 0, 0).is_none());
        assert!(extract_bits(&slot, 0, 257).is_none());
    }

    // ---- §4.4: mapping derivation -------------------------------------

    #[test]
    fn mapping_slot_matches_the_solidity_formula() {
        // Independent check: keccak256(abi.encode(key, base)) computed outside this
        // module via a separate hasher invocation over the same preimage.
        let mut key = [0u8; 32];
        key[12..].copy_from_slice(&[0x11; 20]);
        let mut base = [0u8; 32];
        base[31] = 4;

        let derived = mapping_slot(&key, &base);

        let mut hasher = Keccak256::new();
        hasher.update(key);
        hasher.update(base);
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(derived, expected);
        // And it must not equal the base slot or the key.
        assert_ne!(derived, base);
        assert_ne!(derived, key);
    }

    #[test]
    fn distinguishes_keys_and_base_slots() {
        let key_a = {
            let mut k = [0u8; 32];
            k[31] = 1;
            k
        };
        let key_b = {
            let mut k = [0u8; 32];
            k[31] = 2;
            k
        };
        let base = [0u8; 32];
        assert_ne!(mapping_slot(&key_a, &base), mapping_slot(&key_b, &base));
    }

    #[test]
    fn resolves_a_mapping_with_an_address_key_set() {
        let m = manifest(
            r#"{
                "target": "0x00000000000000000000000000000000000000aa",
                "symbols": {
                    "userBalances": {
                        "kind": "mapping",
                        "slot": "0x4",
                        "key_type": "address",
                        "keys": [
                            "0x00000000000000000000000000000000000A11ce",
                            "0x0000000000000000000000000000000000000B0b"
                        ],
                        "offset_bits": 0, "width_bits": 256
                    }
                }
            }"#,
        );
        let resolved = m.resolve().expect("must resolve");
        let binding = &resolved["userBalances"];
        assert!(binding.is_mapping());
        assert_eq!(binding.declared_key_count(), 2);
        // Address keys are right-aligned into a 32-byte word, which is the ABI
        // encoding: 12 zero bytes of padding, then the 20-byte address.
        assert_eq!(&binding.keys[0][..12], &[0u8; 12]);
        assert_eq!(&binding.keys[0][12..29], &[0u8; 17]);
        assert_eq!(&binding.keys[0][29..], &[0x0a, 0x11, 0xce]);
    }

    #[test]
    fn refuses_a_mapping_with_no_keys() {
        let m = manifest(
            r#"{
                "target": "0x00000000000000000000000000000000000000aa",
                "symbols": {
                    "balances": { "kind": "mapping", "slot": "0x4",
                                  "offset_bits": 0, "width_bits": 256 }
                }
            }"#,
        );
        assert!(matches!(
            m.resolve().unwrap_err(),
            BindingError::EmptyKeySet { .. }
        ));
    }

    #[test]
    fn refuses_a_malformed_key() {
        let m = manifest(
            r#"{
                "target": "0x00000000000000000000000000000000000000aa",
                "symbols": {
                    "balances": { "kind": "mapping", "slot": "0x4",
                                  "key_type": "address",
                                  "keys": ["0xnothex"],
                                  "offset_bits": 0, "width_bits": 256 }
                }
            }"#,
        );
        assert!(matches!(
            m.resolve().unwrap_err(),
            BindingError::BadKey { .. }
        ));
    }

    // ---- §5 item 1: unbound symbols fail at load ----------------------

    #[test]
    fn refuses_a_predicate_symbol_the_manifest_does_not_bind() {
        let m = manifest(
            r#"{
                "target": "0x00000000000000000000000000000000000000aa",
                "symbols": {
                    "totalSupply": { "kind": "slot", "slot": "0x3",
                                     "offset_bits": 0, "width_bits": 256 }
                }
            }"#,
        );
        let required = vec![
            Symbol(vec!["totalSupply".into()]),
            Symbol(vec!["missing".into()]),
        ];
        match m.resolve_for(&required).unwrap_err() {
            BindingError::UnboundSymbol { symbol } => assert_eq!(symbol, "missing"),
            other => panic!("expected UnboundSymbol, got {other}"),
        }
    }

    #[test]
    fn accepts_a_manifest_that_binds_every_required_symbol() {
        let m = manifest(
            r#"{
                "target": "0x00000000000000000000000000000000000000aa",
                "symbols": {
                    "totalSupply": { "kind": "slot", "slot": "0x3",
                                     "offset_bits": 0, "width_bits": 256 },
                    "balances": { "kind": "mapping", "slot": "0x4",
                                  "key_type": "address",
                                  "keys": ["0x0000000000000000000000000000000000000B0b"],
                                  "offset_bits": 0, "width_bits": 256 }
                }
            }"#,
        );
        let required = vec![
            Symbol(vec!["totalSupply".into()]),
            Symbol(vec!["balances".into()]),
        ];
        assert!(m.resolve_for(&required).is_ok());
    }

    #[test]
    fn rejects_an_invalid_target_address() {
        let m = manifest(
            r#"{
                "target": "0xnot-an-address",
                "symbols": {}
            }"#,
        );
        assert!(matches!(
            m.resolve().unwrap_err(),
            BindingError::MissingTarget
        ));
    }

    #[test]
    fn rejects_malformed_json() {
        assert!(matches!(
            BindingManifest::from_json("{").unwrap_err(),
            BindingError::Json(_)
        ));
    }

    #[test]
    fn short_hex_slots_are_left_padded() {
        // `0x3` and a full 64-digit word must resolve to the same slot.
        let short = manifest(
            r#"{
                "target": "0x00000000000000000000000000000000000000aa",
                "symbols": { "x": { "kind": "slot", "slot": "0x3",
                                    "offset_bits": 0, "width_bits": 256 } }
            }"#,
        )
        .resolve()
        .expect("must resolve");
        let full_slot = format!("0x{:0>64}", "3");
        let long = manifest(&format!(
            r#"{{
                "target": "0x00000000000000000000000000000000000000aa",
                "symbols": {{ "x": {{ "kind": "slot", "slot": "{full_slot}",
                                    "offset_bits": 0, "width_bits": 256 }} }}
            }}"#
        ))
        .resolve()
        .expect("must resolve");
        assert_eq!(short["x"].slot, long["x"].slot);
    }
}
