---
title: "Security and deployment"
section: "Reference"
nav_order: 14
description: "Understand the trust boundaries around execution, artifacts, external tools, and the documentation site."
---

## Separate the public site from execution

This documentation site is a static Jekyll build. The Pages workflow builds `docs-site` and uploads the generated site. Publish that output only; do not expose the repository root, `.env`, local configuration, or `.rustyfuzz` as a web directory.

The documentation does not need access to a running fuzz engine. Keeping docs source in the same repository is compatible with deploying the generated site separately. A future public control API requires its own authentication, authorization, isolation, and threat review.

## Execution boundaries

| Boundary | Operational rule |
|---|---|
| RPC provider | Pin state and retain provenance; investigate missing or inconsistent reads |
| Target and generated projects | Treat external-tool execution as untrusted work |
| Evidence files | Verify integrity and preserve original records |
| AI output | Treat proposals as unvalidated until deterministic checks succeed |
| Host credentials | Keep secrets outside published files and untrusted execution environments |

Bounded execution and file checks reduce specific risks. They do not make a compromised host trustworthy or replace operating-system isolation.

## Evidence integrity and secrets

Canonical artifacts carry versioned records and integrity metadata. Security-sensitive filesystem paths use checks against traversal or symlink misuse, and operations apply inventory and size bounds. Verification failures must remain visible.

RPC sanitization removes sensitive URL components in designated persistence/logging paths. That does not guarantee that every user-supplied string, trace, or source-derived report is safe to publish. Inspect exports and keep private configuration out of version control.

## External tool execution

Foundry, Slither, compilers, and generated test projects increase the execution surface. Use isolated workers with minimal credentials and explicit resource/network policy when processing unfamiliar repositories. Do not mount your entire development home directory into such a worker.

## Dependencies and build provenance

The repository includes a dependency vulnerability policy and validation script under `security/` and `scripts/validate_vulnerability_policy.py`. Use current CI results and release verification artifacts to assess a particular build; a documentation statement is not evidence that your binary passed those checks.

## Disclosure

`docs/SECURITY.md` records the current project policy and notes that a dedicated private disclosure channel still needs configuration. Avoid publishing exploit-ready details in public issues. Confirm a private reporting route with the maintainers before sending sensitive vulnerability information.
