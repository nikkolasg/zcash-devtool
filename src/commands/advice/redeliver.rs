use std::fmt::Display;
use std::time::{Duration, Instant};

use anyhow::anyhow;
use clap::Args;
use rand::{RngCore, rngs::OsRng};
use tracing::{info, warn};

use crate::{
    commands::advice::{
        AdviceBatchMessage, RecoveryChallengeMessage, RedeliveryDoneMessage, decode_hex_array,
        identity, store, validate_recovery_proof, wait_message_of_type,
    },
    simplex::SimplexClient,
};

const PAIRING_TIMEOUT: Duration = Duration::from_secs(120);
const PROOF_TIMEOUT: Duration = Duration::from_secs(120);

// Options accepted for the `advice redeliver` command
#[derive(Debug, Args)]
pub(crate) struct Command {
    /// WebSocket URL of the local simplex-chat CLI
    #[arg(long)]
    ws: String,

    /// Invitation link published by the recovered wallet
    #[arg(long)]
    link: String,
}

/// Prints the rejection line required by the recovery protocol and returns an
/// error so the process exits with a non-zero status.
fn reject(reason: impl Display) -> anyhow::Error {
    println!("RECOVERY REJECTED: {reason}");
    anyhow!("recovery rejected: {reason}")
}

impl Command {
    pub(crate) async fn run(self, wallet_dir: Option<String>) -> Result<(), anyhow::Error> {
        let axion_dir = store::require_wallet_dir(wallet_dir.as_ref())?;
        let peers = store::load_peers(&axion_dir)?;
        if peers.is_empty() {
            return Err(anyhow!(
                "no paired identities stored in {}; pair with `advice pair --mode join` while \
                 the peer sends an identity token first",
                axion_dir.join("axion-peers.json").display()
            ));
        }
        let outbox = store::load_outbox(&axion_dir)?;

        let mut simplex = SimplexClient::connect(&self.ws).await?;
        simplex.join(&self.link).await?;
        info!("Joined invitation; waiting for the connection to complete...");
        let name = simplex.wait_contact_connected(PAIRING_TIMEOUT).await?;
        println!("Connected to contact: {name}");

        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        let challenge = RecoveryChallengeMessage {
            v: 1,
            kind: "recovery_challenge".to_string(),
            nonce: hex::encode(nonce),
        };
        simplex
            .send_text(&name, &serde_json::to_string(&challenge)?)
            .await?;
        info!("Sent recovery challenge to {name}");

        let deadline = Instant::now() + PROOF_TIMEOUT;
        let (_, text) = wait_message_of_type(&mut simplex, &name, &["recovery_proof"], deadline)
            .await?
            .ok_or_else(|| {
                reject(format!(
                    "timed out waiting for a recovery proof from {name}"
                ))
            })?;
        let proof = validate_recovery_proof(&text).map_err(reject)?;

        // Match on the stored public key value, never on the new contact's
        // display name: the recovered wallet connects with a fresh profile
        // whose name may differ from, or collide with, the original one.
        // An ambiguous match (same key stored under several contacts) is
        // rejected outright rather than guessing whose outbox to reveal.
        let proof_pubkey = proof.pubkey.to_lowercase();
        let mut matches = peers
            .iter()
            .filter(|(_, peer)| peer.pubkey.to_lowercase() == proof_pubkey);
        let (peer_name, peer) = matches
            .next()
            .ok_or_else(|| reject("recovery proof public key matches no paired identity"))?;
        if matches.next().is_some() {
            return Err(reject(
                "recovery proof public key is stored under multiple contacts; refusing to guess",
            ));
        }
        if proof.j != peer.j {
            warn!(
                "recovery proof claims subkey index {} but the token was stored with index {}",
                proof.j, peer.j
            );
        }

        let pubkey = decode_hex_array::<32>(&proof.pubkey).map_err(reject)?;
        let sig = decode_hex_array::<64>(&proof.sig).map_err(reject)?;
        identity::verify_signature(
            &pubkey,
            &identity::recovery_signing_input(&nonce, &identity::link_binding(&self.link)),
            &sig,
        )
        .map_err(|_| {
            reject(
                "recovery proof signature does not verify against the stored key for this \
                 channel (wrong key, or a proof relayed from another channel)",
            )
        })?;
        info!("Recovery proof verified; peer is the identity paired as {peer_name}");

        // Re-deliver the envelope of every entry regardless of ack status: a
        // recovered wallet needs everything it was ever advised about, acked
        // or not.
        let envelopes: Vec<serde_json::Value> = outbox
            .get(peer_name)
            .map(|entries| entries.iter().map(|entry| entry.envelope.clone()).collect())
            .unwrap_or_default();
        // Envelopes are ~150 bytes; chunks of 40 stay far below the SimpleX
        // message size limit while collapsing N per-message round-trips into
        // ceil(N/40).
        for chunk in envelopes.chunks(40) {
            let batch = AdviceBatchMessage {
                v: 1,
                kind: "advice_batch".to_string(),
                advices: chunk.to_vec(),
            };
            simplex
                .send_text(&name, &serde_json::to_string(&batch)?)
                .await?;
        }
        let count = u32::try_from(envelopes.len())
            .map_err(|_| anyhow!("outbox for {peer_name} is unreasonably large"))?;
        let done = RedeliveryDoneMessage {
            v: 1,
            kind: "redelivery_done".to_string(),
            count,
        };
        simplex
            .send_text(&name, &serde_json::to_string(&done)?)
            .await?;

        println!(
            "continuity proof verified against key held since first pairing (peer {peer_name}, \
             j={}); re-delivered {count} advices",
            peer.j
        );

        Ok(())
    }
}
