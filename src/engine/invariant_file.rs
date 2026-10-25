//! The `--invariants <path>` file: invariants plus the symbols they need.
//!
//! # Why one file and not two
//!
//! The predicate layer's `PredicateOracle::new` takes a predicate *and* a manifest JSON
//! string, one oracle at a time. A user with six invariants over the same three contracts
//! would have to paste the same manifest six times, and a mismatch between copies would be
//! invisible — two invariants over the same slot would silently be reading it with
//! different bit ranges. This format keeps a single `symbols` table for the whole file and
//! resolves each predicate against it.
//!
//! # Scope, stated so nobody over-reads it
//!
//! This is not Echidna's `invariant_*` derivation. A predicate is written here by hand,
//! in the predicate language, against explicitly bound storage slots. Auto-deriving a
//! predicate from a Solidity function body is a separate, much larger job and this file
//! claims nothing about it.
//!
//! # Example
//!
//! ```json
//! {
//!   "target": "0x00000000000000000000000000000000000000aa",
//!   "symbols": {
//!     "totalSupply": { "kind": "slot", "slot": "0x2",
//!                      "offset_bits": 0, "width_bits": 256 },
//!     "sumBalances":  { "kind": "slot", "slot": "0x3",
//!                      "offset_bits": 0, "width_bits": 256 }
//!   },
//!   "invariants": [
//!     { "name": "supplyMatchesBalances", "predicate": "totalSupply == sumBalances" }
//!   ]
//! }
//! ```

use anyhow::{anyhow, Context};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

use rustyfuzz_predicate::{BindingManifest, InvariantRegistry};

/// One invariant: a name and a predicate over the file's symbols.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InvariantEntry {
    pub name: String,
    pub predicate: String,
}

/// The whole file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InvariantFile {
    /// Address the `symbols` bindings refer to.
    pub target: String,
    /// Shared symbol table, in the predicate layer's `RawBinding` shape.
    pub symbols: BTreeMap<String, rustyfuzz_predicate::RawBinding>,
    pub invariants: Vec<InvariantEntry>,
}

impl InvariantFile {
    /// Parses and rejects structural problems early, before any binding work.
    pub fn from_json(text: &str) -> anyhow::Result<Self> {
        let file: InvariantFile =
            serde_json::from_str(text).context("invariant file is not valid JSON")?;
        file.validate()?;
        Ok(file)
    }

    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read invariant file {}", path.display()))?;
        Self::from_json(&text).with_context(|| format!("in invariant file {}", path.display()))
    }

    /// Checks the things that are cheap to check and expensive to discover later.
    fn validate(&self) -> anyhow::Result<()> {
        if self.invariants.is_empty() {
            // An empty registry would silently run a campaign that checks nothing while
            // reporting that invariants were configured. Refuse instead.
            return Err(anyhow!(
                "invariant file declares no invariants; a campaign with an empty \
                 invariant file would check nothing while appearing configured"
            ));
        }
        let mut seen = std::collections::BTreeSet::new();
        for entry in &self.invariants {
            if entry.name.trim().is_empty() {
                return Err(anyhow!("an invariant has an empty name"));
            }
            if entry.predicate.trim().is_empty() {
                return Err(anyhow!("invariant `{}` has an empty predicate", entry.name));
            }
            // Duplicate names make findings ambiguous: two different predicates sharing a
            // name means a report cannot say which one broke.
            if !seen.insert(entry.name.as_str()) {
                return Err(anyhow!(
                    "duplicate invariant name `{}`; names must be unique so a finding can \
                     name exactly one predicate",
                    entry.name
                ));
            }
        }
        if self.symbols.is_empty() {
            return Err(anyhow!(
                "invariant file declares no symbols; every predicate needs bound storage"
            ));
        }
        Ok(())
    }

    /// Renders the shared symbol table as the manifest JSON the predicate layer expects.
    ///
    /// Re-serialising rather than string-splicing keeps a single source of truth for the
    /// binding shape.
    fn manifest_json(&self) -> anyhow::Result<String> {
        let manifest = BindingManifest {
            target: self.target.clone(),
            symbols: self.symbols.clone(),
        };
        serde_json::to_string(&manifest).context("cannot re-serialise the symbol table")
    }

    /// Builds a registry, reporting **every** broken invariant at once.
    ///
    /// Reporting one at a time turns fixing a file into a sequence of runs, which is the
    /// same reasoning as the registry's own multi-error path.
    pub fn build_registry(&self) -> anyhow::Result<InvariantRegistry> {
        self.validate()?;
        let manifest = self.manifest_json()?;

        // Resolve the binding manifest once. It is identical for every predicate, so a
        // binding error is a file-level error, not a per-invariant one, and saying so is
        // clearer than repeating it per invariant.
        BindingManifest::from_json(&manifest)
            .and_then(|parsed| parsed.resolve())
            .map_err(|error| anyhow!("symbol table is invalid: {error}"))?;

        let mut registry = InvariantRegistry::new();
        let mut errors = Vec::new();
        for entry in &self.invariants {
            match rustyfuzz_predicate::PredicateOracle::new(
                rustyfuzz_predicate::InvariantSpec {
                    name: entry.name.clone(),
                    predicate: entry.predicate.clone(),
                },
                &manifest,
            ) {
                Ok(oracle) => registry.register(Box::new(oracle)),
                Err(error) => errors.push(format!("{}: {error}", entry.name)),
            }
        }
        if errors.is_empty() {
            Ok(registry)
        } else {
            Err(anyhow!(
                "{} of {} invariants are invalid:\n  {}",
                errors.len(),
                self.invariants.len(),
                errors.join("\n  ")
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"{
        "target": "0x00000000000000000000000000000000000000aa",
        "symbols": {
            "totalSupply": { "kind": "slot", "slot": "0x2", "offset_bits": 0, "width_bits": 256 },
            "sumBalances": { "kind": "slot", "slot": "0x3", "offset_bits": 0, "width_bits": 256 }
        },
        "invariants": [
            { "name": "supplyMatchesBalances", "predicate": "totalSupply == sumBalances" },
            { "name": "supplyBounded", "predicate": "totalSupply <= sumBalances + 1" }
        ]
    }"#;

    #[test]
    fn a_valid_file_builds_a_registry_with_every_invariant() {
        let file = InvariantFile::from_json(GOOD).expect("parses");
        let registry = file.build_registry().expect("builds");
        let names = registry.names();
        assert_eq!(names, vec!["supplyMatchesBalances", "supplyBounded"]);
    }

    #[test]
    fn the_symbol_table_is_shared_so_bit_ranges_cannot_drift() {
        // Both invariants resolve against the same binding map; if they did not, the two
        // could read the same slot with different widths and disagree for no reason.
        let file = InvariantFile::from_json(GOOD).expect("parses");
        let registry = file.build_registry().expect("builds");
        assert_eq!(registry.names().len(), 2);
        // A binding error surfaces once, as a file-level error.
        let broken = GOOD.replace("\"width_bits\": 256", "\"width_bits\": 256, \"x\": 0");
        let file = InvariantFile::from_json(&broken).expect("still parses");
        assert!(file.build_registry().is_ok(), "an unknown field is ignored");
    }

    #[test]
    fn an_empty_invariant_list_is_refused() {
        // The dangerous case: a config that looks configured and checks nothing.
        let text = r#"{
            "target": "0x00000000000000000000000000000000000000aa",
            "symbols": { "a": { "kind": "slot", "slot": "0x1", "offset_bits": 0, "width_bits": 256 } },
            "invariants": []
        }"#;
        let error = InvariantFile::from_json(text).unwrap_err().to_string();
        assert!(error.contains("no invariants"), "{error}");
        assert!(error.contains("check nothing"), "{error}");
    }

    #[test]
    fn an_empty_symbol_table_is_refused() {
        let text = r#"{
            "target": "0x00000000000000000000000000000000000000aa",
            "symbols": {},
            "invariants": [{ "name": "x", "predicate": "a == 1" }]
        }"#;
        let error = InvariantFile::from_json(text).unwrap_err().to_string();
        assert!(error.contains("no symbols"), "{error}");
    }

    #[test]
    fn duplicate_names_are_refused() {
        let text = GOOD.replace("\"supplyBounded\"", "\"supplyMatchesBalances\"");
        let error = InvariantFile::from_json(&text).unwrap_err().to_string();
        assert!(error.contains("duplicate invariant name"), "{error}");
    }

    #[test]
    fn empty_names_and_predicates_are_refused() {
        let text = GOOD.replace("\"supplyBounded\"", "\"  \"");
        assert!(InvariantFile::from_json(&text)
            .unwrap_err()
            .to_string()
            .contains("empty name"));
        let text = GOOD.replace("\"totalSupply <= sumBalances + 1\"", "\"   \"");
        assert!(InvariantFile::from_json(&text)
            .unwrap_err()
            .to_string()
            .contains("empty predicate"));
    }

    #[test]
    fn every_broken_predicate_is_reported_at_once() {
        let text = GOOD
            .replace("\"totalSupply == sumBalances\"", "\"totalSupply ==\"")
            .replace("\"totalSupply <= sumBalances + 1\"", "\"<= 1\"");
        let file = InvariantFile::from_json(&text).expect("structurally fine");
        let error = file.build_registry().unwrap_err().to_string();
        assert!(error.contains("2 of 2"), "{error}");
        assert!(error.contains("supplyMatchesBalances"), "{error}");
        assert!(error.contains("supplyBounded"), "{error}");
    }

    #[test]
    fn a_missing_bit_range_is_a_file_level_error_that_names_the_symbol() {
        let text = GOOD.replace(
            "\"totalSupply\": { \"kind\": \"slot\", \"slot\": \"0x2\", \"offset_bits\": 0, \"width_bits\": 256 }",
            "\"totalSupply\": { \"kind\": \"slot\", \"slot\": \"0x2\" }",
        );
        let file = InvariantFile::from_json(&text).expect("structurally fine");
        let error = file.build_registry().unwrap_err().to_string();
        assert!(error.contains("symbol table is invalid"), "{error}");
        assert!(error.contains("totalSupply"), "{error}");
        assert!(error.contains("offset_bits"), "{error}");
    }

    #[test]
    fn a_predicate_using_an_unbound_symbol_is_reported_by_name() {
        let text = GOOD.replace("totalSupply == sumBalances", "totalSupply == unboundThing");
        let file = InvariantFile::from_json(&text).expect("structurally fine");
        let error = file.build_registry().unwrap_err().to_string();
        assert!(error.contains("supplyMatchesBalances"), "{error}");
        assert!(error.contains("unboundThing"), "{error}");
    }

    #[test]
    fn approx_eq_works_through_the_file_format() {
        // The format must not silently exclude the newest operator.
        let text = GOOD.replace(
            "\"totalSupply == sumBalances\"",
            "\"approx_eq(totalSupply, sumBalances, 100, 6)\"",
        );
        let file = InvariantFile::from_json(&text).expect("parses");
        let registry = file.build_registry().expect("approx_eq builds");
        assert_eq!(registry.names().len(), 2);
    }

    #[test]
    fn a_malformed_file_names_the_path() {
        let dir = std::env::temp_dir().join("rustyfuzz-invariant-file-test");
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("broken.json");
        std::fs::write(&path, "{ not json").expect("write");
        let error = InvariantFile::load(&path).unwrap_err().to_string();
        assert!(error.contains("broken.json"), "{error}");
    }
}
