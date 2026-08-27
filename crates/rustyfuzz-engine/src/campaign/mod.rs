//! Campaign infrastructure: budgeting and telemetry.
//!
//! TODO(stage-4): the two harness runtimes currently living in the root
//! fuzzer will move under `campaign::{runtime,worker}` when worker boundaries
//! are split; budget/telemetry primitives already live here.

pub mod budget;
pub mod telemetry;
