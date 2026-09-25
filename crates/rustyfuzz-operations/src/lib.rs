pub mod alerts;
pub mod backup;
pub mod error;
pub mod integrity;
pub mod inventory;
pub mod metrics;
pub mod models;
pub mod recovery;
pub mod restore;

pub use alerts::{derive_alerts, derive_alerts_at, derive_events, derive_events_from_report};
pub use backup::{create_backup, create_backup_for_run};
pub use error::OperationsError;
pub use integrity::{verify_campaign, verify_run_root};
pub use inventory::{health, inventory, readiness};
pub use metrics::render as render_prometheus;
pub use models::*;
pub use recovery::run_recovery_drill;
pub use restore::{
    preflight_backup, publish_staged_restore, restore_backup, stage_backup,
    validate_restore_target, RestoreFailure, StagedRestore,
};
