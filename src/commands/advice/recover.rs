use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::anyhow;
use clap::Args;
use rand::rngs::OsRng;
use tracing::{info, warn};
use zcash_client_backend::{data_api::WalletWrite, proto::service};
use zcash_client_sqlite::{WalletDb, util::SystemClock};
use zcash_protocol::consensus::BlockHeight;

use crate::{
    commands::advice::{
        RecoveryProofMessage, decode_hex_array, identity, validate_advice_batch,
        validate_recovery_challenge, validate_redelivery_done,
        verify::{format_zec, validate_envelope, verify_advice},
        wait_message_of_type,
    },
    config::get_wallet_network,
    data::get_db_paths,
    remote::ConnectionArgs,
    simplex::SimplexClient,
};

// Options accepted for the `advice recover` command
#[derive(Debug, Args)]
pub(crate) struct Command {
    /// WebSocket URL of the local simplex-chat CLI
    #[arg(long)]
    ws: String,

    /// age identity file to decrypt the restored wallet's mnemonic with
    #[arg(long)]
    identity: String,

    /// Identity subkey index to prove ownership of
    #[arg(long, default_value_t = 0)]
    index: u32,

    /// File to write the fresh invitation link to
    #[arg(long)]
    link_out: PathBuf,

    /// How long to wait for the peer and the re-delivery, in seconds
    #[arg(long, default_value_t = 600)]
    timeout: u64,

    #[command(flatten)]
    connection: ConnectionArgs,
}

impl Command {
    pub(crate) async fn run(self, wallet_dir: Option<String>) -> Result<(), anyhow::Error> {
        if wallet_dir.is_none() {
            return Err(anyhow!(
                "advice recover requires -w/--wallet-dir pointing at the restored wallet"
            ));
        }
        let params = get_wallet_network(wallet_dir.as_ref())?;
        let (_, db_path) = get_db_paths(wallet_dir.as_ref());
        let mut db_data = WalletDb::for_path(db_path, params, SystemClock, OsRng)?;

        // Derive the identity subkey up front so a wrong age identity file
        // fails before the peer is made to wait on a channel.
        let sk = identity::wallet_signing_key(wallet_dir.as_ref(), &self.identity, self.index)?;
        let pubkey = identity::public_key_bytes(&sk);

        let mut simplex = SimplexClient::connect(&self.ws).await?;
        let link = simplex.create_invitation().await?;
        println!("{link}");
        std::fs::write(&self.link_out, &link)?;
        info!("Invitation link written to {}", self.link_out.display());

        let timeout = Duration::from_secs(self.timeout);
        let deadline = Instant::now() + timeout;
        info!("Waiting for the re-delivering peer to join the invitation...");
        let name = simplex.wait_contact_connected(timeout).await?;
        println!("Connected to contact: {name}");

        let (_, text) =
            wait_message_of_type(&mut simplex, &name, &["recovery_challenge"], deadline)
                .await?
                .ok_or_else(|| anyhow!("timed out waiting for a recovery challenge from {name}"))?;
        let challenge = validate_recovery_challenge(&text)
            .map_err(|e| anyhow!("invalid recovery challenge from {name}: {e}"))?;
        let nonce = decode_hex_array::<32>(&challenge.nonce)?;

        // The signature binds this channel's invitation link: a proof relayed
        // by a man-in-the-middle onto a different channel fails verification.
        let sig = sk.sign(&identity::recovery_signing_input(
            &nonce,
            &identity::link_binding(&link),
        ));
        let proof = RecoveryProofMessage {
            v: 1,
            kind: "recovery_proof".to_string(),
            j: self.index,
            pubkey: hex::encode(pubkey),
            sig: hex::encode(sig.to_bytes()),
        };
        simplex
            .send_text(&name, &serde_json::to_string(&proof)?)
            .await?;
        info!(
            "Answered the recovery challenge with identity subkey index {}",
            self.index
        );
        let t0 = Instant::now();

        // Collect the whole re-delivered batch before touching the chain: one
        // chain-tip update then targeted per-advice verification, no scan.
        let mut envelopes = Vec::new();
        let mut skipped = 0u32;
        let advertised_count = loop {
            let (kind, text) = wait_message_of_type(
                &mut simplex,
                &name,
                &["advice", "advice_batch", "redelivery_done"],
                deadline,
            )
            .await?
            .ok_or_else(|| anyhow!("timed out waiting for re-delivered advice from {name}"))?;
            match kind.as_str() {
                // Batched form (the normal case); each entry is validated as
                // strictly as a standalone advice message.
                "advice_batch" => match validate_advice_batch(&text) {
                    Ok(batch) => {
                        for entry in &batch.advices {
                            match serde_json::to_string(entry)
                                .map_err(|e| e.to_string())
                                .and_then(|s| validate_envelope(&s))
                            {
                                Ok(envelope) => envelopes.push(envelope),
                                Err(e) => {
                                    println!("ADVICE REJECTED: {e}; skipping");
                                    skipped += 1;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        // A wholesale batch-parse failure loses up to 40
                        // envelopes at once and we cannot know how many, so it
                        // must not be folded into `skipped` as a single advice.
                        // Surface it distinctly and let the advertised/received
                        // reconciliation below flag the shortfall loudly.
                        warn!(
                            "an entire re-delivered batch failed to parse ({e}); its advices are \
                             lost and the advertised/received counts will not reconcile"
                        );
                    }
                },
                "advice" => match validate_envelope(&text) {
                    Ok(envelope) => envelopes.push(envelope),
                    Err(e) => {
                        println!("ADVICE REJECTED: {e}; skipping");
                        skipped += 1;
                    }
                },
                _ => {
                    let done = validate_redelivery_done(&text)
                        .map_err(|e| anyhow!("invalid redelivery_done from {name}: {e}"))?;
                    break done.count;
                }
            }
        };
        // Everything up to here is messaging: constant per payment and
        // independent of chain length. Chain work is timed separately so the
        // demo can compare it apples-to-apples with a rescan.
        let t_transfer = t0.elapsed();
        let received = envelopes.len() + skipped as usize;
        if advertised_count as usize != received {
            warn!("peer advertised {advertised_count} advices but {received} arrived");
        }
        info!("Received {} re-delivered advices from {name}", received);

        let mut client = self.connection.connect(params, wallet_dir.as_ref()).await?;
        let chain_start = Instant::now();
        let latest = client
            .get_latest_block(service::ChainSpec::default())
            .await?
            .into_inner();
        let tip_height = BlockHeight::from_u32(
            u32::try_from(latest.height).map_err(|_| anyhow!("chain tip height out of range"))?,
        );
        db_data.update_chain_tip(tip_height)?;
        info!("Chain tip updated to height {}", tip_height);

        // Envelope signatures cannot be checked here: the peers file holding
        // the sender's identity key is gone with the lost device (only the
        // seed survived). Every envelope is therefore unverifiable-but-chain-
        // verified — warned once, not per envelope. Post-recovery, envelope
        // signatures re-become checkable once the wallet re-pairs with its
        // peers.
        if !envelopes.is_empty() {
            warn!(
                "recovered wallet has no stored peer identities; envelope signatures are \
                 unverifiable until re-pairing (chain verification still governs)"
            );
        }

        let mut verified = 0u32;
        let mut total_value = 0u64;
        // TODO(privacy): recover still uses GetTransaction per advice
        for envelope in &envelopes {
            // A single bad advice (including server errors fetching it) must
            // not abort the whole recovery; each failure is reported and the
            // batch continues.
            match verify_advice(&params, &mut db_data, &mut client, tip_height, envelope).await {
                Ok(Ok(outcome)) => {
                    verified += 1;
                    total_value += outcome.value;
                    println!(
                        "ADVICE VERIFIED: received {} ZEC in tx {} at height {} (pool={}, index={})",
                        format_zec(outcome.value),
                        envelope.txid,
                        outcome.mined_height,
                        outcome.pool,
                        outcome.index,
                    );
                }
                Ok(Err(reason)) => {
                    skipped += 1;
                    println!("ADVICE REJECTED: {reason} (tx {}); skipping", envelope.txid);
                }
                Err(e) => {
                    skipped += 1;
                    println!(
                        "ADVICE SKIPPED: error verifying tx {}: {e}; skipping",
                        envelope.txid
                    );
                }
            }
        }
        let t_chain = chain_start.elapsed();
        let t_total = t0.elapsed();

        println!("verified {verified} advices, skipped {skipped}");
        println!(
            "RECOVERY COMPLETE: restored {} payments totalling {} ZEC in {}ms \
             (advice transfer {}ms, chain verification {}ms)",
            verified,
            format_zec(total_value),
            t_total.as_millis(),
            t_transfer.as_millis(),
            t_chain.as_millis(),
        );
        println!(
            "timing: total {:?} (challenge answered to done), advice transfer {:?} \
             (messaging, constant in chain size), chain verification {:?} \
             (targeted decryptions, the rescan-equivalent)",
            t_total, t_transfer, t_chain
        );

        Ok(())
    }
}
