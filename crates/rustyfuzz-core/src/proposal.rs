//! Typed AI proposals and the mandatory validation seam (Stage 4C).
//!
//! Global invariant #4: AI proposes; RustyFuzz validates. An [`AiProposal`]
//! can never become a finding, a proof, or trusted state by itself — it must
//! pass through [`AiProposal::validate`] into [`ProposalValidation`], and
//! even then it is only *validated advice* with recorded provenance.

use serde::{Deserialize, Serialize};

/// What kind of assistance the AI provided.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalKind {
    SuggestSeeds,
    SuggestInvariants,
    AnalyzeCoverageGap,
    SuggestMutationStrategy,
    GenerateHarness,
    ExplainFinding,
    TriageCandidate,
}

/// Recorded provenance of an AI interaction (hashes only; prompts/responses
/// may contain license-sensitive content, hashes keep artifacts lean).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AiProposal {
    /// Provider identifier (e.g. `openai`, `noop`). Provider-neutral contract.
    pub provider: String,
    /// Model name as reported/configured.
    pub model: String,
    /// Task the proposal belongs to.
    pub kind: ProposalKind,
    /// Stable hash of the request payload.
    pub request_hash: String,
    /// Stable hash of the raw response payload.
    pub response_hash: String,
    /// Raw proposal body (opaque to this crate; interpreted by validation).
    pub body: String,
    /// Validation state; starts as unvalidated by construction.
    pub validation: ProposalValidation,
}

impl AiProposal {
    /// Records an unvalidated AI proposal from provider provenance.
    ///
    /// This constructor exists so no code path can accidentally create a
    /// "pre-validated" proposal.
    pub fn unvalidated(
        provider: impl Into<String>,
        model: impl Into<String>,
        kind: ProposalKind,
        request_hash: impl Into<String>,
        response_hash: impl Into<String>,
        body: impl Into<String>,
    ) -> Self {
        Self {
            provider: provider.into(),
            model: model.into(),
            kind,
            request_hash: request_hash.into(),
            response_hash: response_hash.into(),
            body: body.into(),
            validation: ProposalValidation::Unvalidated,
        }
    }

    /// Applies a deterministic validation outcome produced outside the AI path.
    pub fn validate(mut self, accepted: bool, detail: impl Into<String>) -> Self {
        self.validation = if accepted {
            ProposalValidation::Accepted {
                detail: detail.into(),
            }
        } else {
            ProposalValidation::Rejected {
                detail: detail.into(),
            }
        };
        self
    }
}

/// Outcome of deterministic validation of one proposal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProposalValidation {
    /// Not yet checked; such proposals must not influence fuzzing decisions.
    Unvalidated,
    /// Deterministic checks passed (e.g. seed decodes, calldata well-formed).
    Accepted { detail: String },
    /// Deterministic checks failed; recorded for auditability.
    Rejected { detail: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proposals_start_unvalidated_and_validation_is_explicit() {
        let proposal = AiProposal::unvalidated(
            "provider-x",
            "model-y",
            ProposalKind::SuggestSeeds,
            "req-hash",
            "resp-hash",
            "{}",
        );
        assert_eq!(proposal.validation, ProposalValidation::Unvalidated);

        let accepted = proposal.clone().validate(true, "seed decodes");
        assert!(matches!(
            accepted.validation,
            ProposalValidation::Accepted { .. }
        ));

        let rejected = proposal.validate(false, "malformed calldata");
        assert!(matches!(
            rejected.validation,
            ProposalValidation::Rejected { .. }
        ));
    }
}
