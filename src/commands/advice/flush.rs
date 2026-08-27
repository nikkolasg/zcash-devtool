use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::anyhow;
use clap::Args;
use tracing::info;

use crate::{
    commands::advice::{
        process_ack_message,
        store::{self, OutboxStatus},
        wait_message_of_type,
    },
    config::get_wallet_network,
    simplex::SimplexClient,
};

// Options accepted for the `advice flush` command
#[derive(Debug, Args)]
pub(crate) struct Command {
    /// WebSocket URL of the local simplex-chat CLI
    #[arg(long)]
    ws: String,

    /// Display name of the SimpleX contact whose outbox to flush
    #[arg(long)]
    to: String,

    /// How long to wait for acks after re-sending, in seconds
    #[arg(long, default_value_t = 30)]
    ack_timeout: u64,

    /// Age in seconds past which an unacknowledged advice is reported as
    /// overdue
    #[arg(long, default_value_t = 86_400)]
    overdue_secs: u64,
}

/// Returns true when a pending advice sent at `sent_at` (unix seconds)
/// counts as overdue at `now`: strictly older than `overdue_secs`, or of
/// unknown age (entries written before send timestamps were recorded are
/// surfaced as overdue rather than silently fresh).
fn is_overdue(sent_at: Option<u64>, now: u64, overdue_secs: u64) -> bool {
    match sent_at {
        None => true,
        Some(sent) => now.saturating_sub(sent) > overdue_secs,
    }
}

impl Command {
    /// The sender-side re-send/overdue loop (spec 1.3.2): reports outbox
    /// state, surfaces advice unacknowledged past `--overdue-secs`, re-sends
    /// every pending envelope verbatim, and processes the acks (and rotation
    /// messages, spec 1.3.5) that come back.
    pub(crate) async fn run(self, wallet_dir: Option<String>) -> Result<(), anyhow::Error> {
        let axion_dir = store::require_wallet_dir(wallet_dir.as_ref())?;
        let params = get_wallet_network(wallet_dir.as_ref())?;
        let stored_pubkey = store::load_peers(&axion_dir)?
            .get(&self.to)
            .map(|peer| peer.pubkey.clone());

        let outbox = store::load_outbox(&axion_dir)?;
        let entries = outbox.get(&self.to).cloned().unwrap_or_default();
        let count = |status: OutboxStatus| entries.iter().filter(|e| e.status == status).count();
        let pending: Vec<&store::OutboxEntry> = entries
            .iter()
            .filter(|e| e.status == OutboxStatus::Pending)
            .collect();
        println!(
            "outbox for {}: {} total, {} pending, {} acked, {} rejected",
            self.to,
            entries.len(),
            pending.len(),
            count(OutboxStatus::Acked),
            count(OutboxStatus::Rejected),
        );

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| anyhow!("system clock predates the Unix epoch: {e}"))?
            .as_secs();
        for entry in &pending {
            if !is_overdue(entry.sent_at, now, self.overdue_secs) {
                continue;
            }
            let txid = entry.txid().unwrap_or("<unknown>");
            match entry.sent_at {
                Some(sent) => println!(
                    "OVERDUE: txid {txid} unacknowledged for {}s",
                    now.saturating_sub(sent)
                ),
                None => println!(
                    "OVERDUE: txid {txid} unacknowledged, age unknown (sent before send \
                     timestamps were recorded)"
                ),
            }
        }

        let mut simplex = SimplexClient::connect(&self.ws).await?;

        if pending.is_empty() {
            println!("no pending advice for {}; nothing to re-send", self.to);
            return Ok(());
        }

        // Re-send every pending envelope verbatim (signature included),
        // oldest first — the outbox preserves append order.
        for entry in &pending {
            simplex
                .send_text(&self.to, &serde_json::to_string(&entry.envelope)?)
                .await?;
        }
        println!(
            "re-sent {} pending advice envelope(s) to {}",
            pending.len(),
            self.to
        );

        // Acks resolve entries by txid, so duplicates collapse into one
        // unresolved slot (set_outbox_status marks every matching entry).
        let mut unresolved: Vec<String> = Vec::new();
        for entry in &pending {
            if let Some(txid) = entry.txid() {
                let txid = txid.to_ascii_lowercase();
                if !unresolved.contains(&txid) {
                    unresolved.push(txid);
                }
            }
        }
        let total = unresolved.len();

        info!(
            "Waiting up to {}s for acks from {}",
            self.ack_timeout, self.to
        );
        let deadline = Instant::now() + Duration::from_secs(self.ack_timeout);
        while !unresolved.is_empty() {
            let Some((_, text)) =
                wait_message_of_type(&mut simplex, &self.to, &["ack"], deadline).await?
            else {
                break;
            };
            if let Some(txid) = process_ack_message(
                &axion_dir,
                &params,
                &self.to,
                stored_pubkey.as_deref(),
                &unresolved,
                &text,
            )? {
                unresolved.retain(|t| t != &txid);
            }
        }
        println!(
            "flush complete: {} resolved, {} still pending",
            total - unresolved.len(),
            unresolved.len()
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::is_overdue;

    #[test]
    fn overdue_classification() {
        // Unknown send time: always overdue (surfaced, never silently fresh).
        assert!(is_overdue(None, 1_000_000, 86_400));
        // Fresh.
        assert!(!is_overdue(Some(999_990), 1_000_000, 86_400));
        // Exactly at the threshold is not yet overdue (strictly older than).
        assert!(!is_overdue(Some(913_600), 1_000_000, 86_400));
        // One second past the threshold is.
        assert!(is_overdue(Some(913_599), 1_000_000, 86_400));
        // A send timestamp in the future (clock skew) is not overdue.
        assert!(!is_overdue(Some(1_000_100), 1_000_000, 86_400));
        // Zero threshold: anything older than "now" is overdue.
        assert!(is_overdue(Some(999_999), 1_000_000, 0));
        assert!(!is_overdue(Some(1_000_000), 1_000_000, 0));
    }
}
