use serde_json::json;
use chrono::Utc;
use crate::common::oracle::VulnType;
use crate::common::types::Snapshot;
use alloy::hex;
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// DiscordNotifier manages remote alerts for vulnerability discoveries.
/// It utilizes Discord Webhooks to send rich embeds containing exploit metadata.
pub struct DiscordNotifier {
    webhook_url: String,
    client: reqwest::Client,
    last_sent: Arc<Mutex<Instant>>,
    cooldown: Duration,
}

impl DiscordNotifier {
    /// Creates a new notifier by pulling the webhook URL from the environment.
    pub fn new() -> Self {
        let webhook_url = std::env::var("DISCORD_WEBHOOK_URL").unwrap_or_default();
        Self {
            webhook_url,
            client: reqwest::Client::new(),
            last_sent: Arc::new(Mutex::new(Instant::now() - Duration::from_secs(60))),
            cooldown: Duration::from_secs(10),
        }
    }

    /// Dispatches a formatted alert to Discord.
    pub async fn notify_discovery(
        &self, 
        vuln_type: &VulnType, 
        snapshot: &Snapshot, 
        mrenclave: Option<&[u8]>,
        poc: Option<String>,
    ) -> anyhow::Result<()> {
        // Fallback: If webhook is not configured, log finding locally
        if self.webhook_url.is_empty() {
            log::warn!("Discord Notifier unconfigured. Fallback log: Found vulnerability {:?} in Snapshot {}", vuln_type, snapshot.id);
            return Ok(());
        }

        // Rate limiting: Prevent webhook throttling during high-frequency discovery
        {
            let mut last_sent = self.last_sent.lock();
            if last_sent.elapsed() < self.cooldown {
                return Ok(());
            }
            *last_sent = Instant::now();
        }

        let mut fields = vec![
            json!({ "name": "Severity", "value": "🔴 Critical (P0/P1)", "inline": true }),
            json!({ "name": "Vulnerability", "value": format!("`{:?}`", vuln_type), "inline": true }),
            json!({ "name": "Snapshot ID", "value": format!("`{}`", snapshot.id), "inline": true }),
            json!({ "name": "Sequence Depth", "value": format!("`{}` steps", snapshot.depth), "inline": true }),
        ];

        if let Some(mr) = mrenclave {
            fields.push(json!({ "name": "SGX Attestation (MRENCLAVE)", "value": format!("`0x{}`", hex::encode(mr)), "inline": false }));
        }

        let mut description = "A state-tree branch has violated a protocol invariant. Multi-step transaction sequence verified.".to_string();
        if let Some(poc_content) = poc {
            description.push_str(&format!("\n\n**Proof of Concept:**\n```rust\n{}\n```", poc_content));
        }

        let payload = json!({
            "username": "RustyFuzz Guardian",
            "avatar_url": "https://raw.githubusercontent.com/rust-lang/rust-artwork/master/logo/rust-logo-512x512.png",
            "embeds": [{
                "title": "🔓 Exploit Path Found",
                "description": description,
                "color": 0xE74C3C,
                "fields": fields,
                "footer": { "text": "Offensive Research Platform v0.1.0" },
                "timestamp": Utc::now().to_rfc3339()
            }]
        });

        // Fallback: Log if transport fails or returns an error status
        match self.client.post(&self.webhook_url).json(&payload).send().await {
            Ok(resp) if resp.status().is_success() => {
                log::info!("Discord notification sent successfully for {:?}", vuln_type);
            }
            Ok(resp) => {
                log::error!("Discord notification failed (status: {}). Fallback log: Found {:?} in Snapshot {}", resp.status(), vuln_type, snapshot.id);
            }
            Err(e) => {
                log::error!("Discord transport error: {}. Fallback log: Found {:?} in Snapshot {}", e, vuln_type, snapshot.id);
            }
        }
        Ok(())
    }
}