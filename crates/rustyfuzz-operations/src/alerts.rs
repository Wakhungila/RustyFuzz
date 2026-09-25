use crate::inventory::InventoryReport;
use crate::models::{Alert, AlertSeverity, CampaignState, IntegrityState, OperationalEvent};
use crate::OperationConfig;
use sha2::Digest;
use std::collections::BTreeMap;

const STALE_AFTER_SECS: u64 = 300;

pub fn derive_alerts(config: &OperationConfig) -> Result<Vec<Alert>, crate::OperationsError> {
    let report = crate::inventory(config)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default();
    Ok(derive_alerts_at(&report, now))
}

pub fn derive_alerts_at(report: &InventoryReport, now_unix: u64) -> Vec<Alert> {
    let mut alerts = BTreeMap::new();
    for campaign in &report.campaigns {
        let status = &campaign.status;
        let observed_at_unix = status.updated_at_unix;
        let mut add = |code: &str, kind: &str, severity: AlertSeverity, message: String| {
            let alert = Alert {
                schema_version: crate::OPERATIONS_SCHEMA_VERSION,
                alert_id: deterministic_id("alert", code, &status.campaign_id),
                severity,
                code: code.to_string(),
                kind: kind.to_string(),
                campaign_id: Some(status.campaign_id.clone()),
                message,
                created_at_unix: observed_at_unix,
                updated_at_unix: observed_at_unix,
                observed_at_unix,
                active: true,
            };
            alerts.insert(alert.alert_id.clone(), alert);
        };
        if status.integrity == IntegrityState::Failed {
            add(
                "integrity_failed",
                "integrity",
                AlertSeverity::Critical,
                format!(
                    "Campaign {} failed integrity verification.",
                    status.campaign_id
                ),
            );
        }
        if status.integrity == IntegrityState::Unknown {
            add(
                "integrity_unknown",
                "integrity",
                AlertSeverity::Warning,
                format!(
                    "Campaign {} has unknown integrity status.",
                    status.campaign_id
                ),
            );
        }
        if status.terminal && status.state == CampaignState::Failed {
            add(
                "terminal_failed",
                "campaign",
                AlertSeverity::Critical,
                format!(
                    "Campaign {} finished in a failed state.",
                    status.campaign_id
                ),
            );
        }
        if status.state == CampaignState::Running
            && now_unix.saturating_sub(status.updated_at_unix) > STALE_AFTER_SECS
        {
            add(
                "campaign_stale",
                "campaign",
                AlertSeverity::Warning,
                format!(
                    "Campaign {} has not updated recently and may be stalled.",
                    status.campaign_id
                ),
            );
        }
    }
    alerts.into_values().collect()
}

pub fn derive_events(
    config: &OperationConfig,
) -> Result<Vec<OperationalEvent>, crate::OperationsError> {
    let report = crate::inventory(config)?;
    Ok(derive_events_from_report(&report))
}

pub fn derive_events_from_report(report: &InventoryReport) -> Vec<OperationalEvent> {
    let mut events = BTreeMap::new();
    for campaign in &report.campaigns {
        let status = &campaign.status;
        let key = format!(
            "{}:{}:{}:{}:{}:{}",
            status.campaign_id,
            status.state.state_name(),
            status.phase.phase_name(),
            status.terminal,
            status.integrity.integrity_name(),
            status.updated_at_unix
        );
        let event = OperationalEvent {
            schema_version: crate::OPERATIONS_SCHEMA_VERSION,
            event_id: deterministic_id("event", "campaign_status_snapshot", &key),
            severity: event_severity(status.integrity, status.terminal, status.state),
            campaign_id: status.campaign_id.clone(),
            kind: "campaign_status_snapshot".to_string(),
            message: format!(
                "Campaign {} is {} in phase {}. ",
                status.campaign_id,
                status.state.state_name(),
                status.phase.phase_name()
            )
            .trim_end()
            .to_string(),
            state: status.state.state_name().to_string(),
            phase: status.phase.phase_name().to_string(),
            terminal: status.terminal,
            integrity: status.integrity.integrity_name().to_string(),
            created_at_unix: status.updated_at_unix,
            updated_at_unix: status.updated_at_unix,
            observed_at_unix: status.updated_at_unix,
        };
        events.insert(event.event_id.clone(), event);
    }
    events.into_values().collect()
}

fn event_severity(
    integrity: IntegrityState,
    terminal: bool,
    state: CampaignState,
) -> AlertSeverity {
    if integrity == IntegrityState::Failed || (terminal && state == CampaignState::Failed) {
        AlertSeverity::Critical
    } else if integrity == IntegrityState::Unknown || state == CampaignState::Running {
        AlertSeverity::Warning
    } else {
        AlertSeverity::Info
    }
}

fn deterministic_id(prefix: &str, kind: &str, subject: &str) -> String {
    let digest = sha2::Sha256::digest(format!("{prefix}:{kind}:{subject}").as_bytes());
    format!("{prefix}_{}", hex::encode(digest))
}

impl CampaignState {
    fn state_name(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Partial => "partial",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
        }
    }
}

impl crate::models::CampaignPhase {
    fn phase_name(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Discovered => "discovered",
            Self::Preparing => "preparing",
            Self::Fuzzing => "fuzzing",
            Self::Verifying => "verifying",
            Self::Finalizing => "finalizing",
            Self::Terminal => "terminal",
        }
    }
}

impl IntegrityState {
    fn integrity_name(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Verified => "verified",
            Self::Failed => "failed",
        }
    }
}
