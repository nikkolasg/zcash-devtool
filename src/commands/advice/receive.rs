use std::convert::Infallible;
use std::fmt::Display;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::anyhow;
use clap::Args;
use ed25519_zebra::SigningKey;
use rand::rngs::OsRng;
use tracing::{debug, info, warn};
use zcash_client_backend::{
    data_api::{
        WalletRead,
        chain::{BlockSource, ChainState, error::Error as ChainError, scan_cached_blocks},
        scanning::ScanRange,
    },
    proto::compact_formats::CompactBlock,
};
use zcash_client_sqlite::{FsBlockDb, WalletDb, chain::BlockMeta, util::SystemClock};
use zcash_protocol::consensus::{BlockHeight, Parameters};

use crate::{
    commands::advice::{
        AckMessage, EnvelopeAuth, check_envelope_signature, identity, mint_next_address,
        parse_txid, store,
        verify::{PeekOutcome, format_zec, peek_advised_output, validate_envelope, verify_advice},
        wait_message_of_type,
    },
    config::get_wallet_network,
    data::get_db_paths,
    error,
    helpers::scan,
    remote::ConnectionArgs,
    simplex::SimplexClient,
};
use tonic::transport::Channel;
use zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient;

/// The maximum number of blocks downloaded and scanned in one range at a time,
/// matching `wallet sync` so the `GetBlockRange` windows the indexer observes
/// are the same ones a normal sync of this gap would request.
const BATCH_SIZE: u32 = 10_000;

// Options accepted for the `advice receive` command
#[derive(Debug, Args)]
pub(crate) struct Command {
    /// WebSocket URL of the local simplex-chat CLI
    #[arg(long)]
    ws: String,

    /// Display name of the SimpleX contact to accept advice from
    #[arg(long)]
    from: String,

    /// How long to wait for an advice message, in seconds
    #[arg(long, default_value_t = 600)]
    timeout: u64,

    /// age identity file for the wallet mnemonic; when given, acknowledge
    /// the advice with a signed ack carrying the next fresh address
    #[arg(long)]
    identity: Option<String>,

    /// Identity subkey index to sign acks with, used when the peers file has
    /// no recorded index for this contact
    #[arg(long, default_value_t = 0)]
    index: u32,

    /// Lower privacy: fetches only the advised transaction, revealing its txid
    /// to the indexer; skips the full scan (the background scanner backstops
    /// completeness).
    #[arg(long)]
    fast_sync: bool,

    #[command(flatten)]
    connection: ConnectionArgs,
}

/// Prints the rejection line required by the advice protocol and returns an
/// error so the process exits with a non-zero status.
fn reject(reason: impl Display) -> anyhow::Error {
    println!("ADVICE REJECTED: {reason}");
    anyhow!("advice rejected: {reason}")
}

/// Builds a signed ack for `txid_str` (display-order hex, already validated).
/// `counter` is this relationship's next monotonic sequence value (the replay
/// guard the sender enforces).
fn build_signed_ack(
    sk: &SigningKey,
    txid_str: &str,
    status: &str,
    counter: u64,
    next_address: String,
) -> Result<AckMessage, anyhow::Error> {
    let txid = parse_txid(txid_str)?;
    let sig = sk.sign(&identity::ack_signing_input(
        txid.as_ref(),
        crate::commands::advice::ack_status_byte(status)?,
        counter,
        &next_address,
    ));
    Ok(AckMessage {
        v: 1,
        kind: "ack".to_string(),
        txid: txid_str.to_owned(),
        status: status.to_owned(),
        next_address,
        counter,
        sig: Some(hex::encode(sig.to_bytes())),
    })
}

/// Best-effort delivery of a signed invalid-ack on a rejection path: an ack
/// failure must never mask the rejection exit, so errors are only warned
/// about.
async fn send_invalid_ack(
    simplex: &mut SimplexClient,
    axion_dir: &Path,
    contact: &str,
    sk: Option<&SigningKey>,
    txid_str: &str,
) {
    let Some(sk) = sk else { return };
    let result = async {
        // Invalid-acks draw from the same monotonic sequence as accepted ones,
        // so the sender orders every signed message from this recipient.
        let counter = store::next_outgoing_counter(axion_dir, contact)?;
        let ack = build_signed_ack(sk, txid_str, "invalid", counter, String::new())?;
        simplex
            .send_text(contact, &serde_json::to_string(&ack)?)
            .await
    }
    .await;
    match result {
        Ok(()) => println!("ack sent: invalid"),
        Err(e) => warn!("failed to send invalid-ack to {contact}: {e}"),
    }
}

/// Splits each suggested scan range into consecutive batches of at most
/// `batch_size` blocks, preserving order and priority. This is the same
/// batching `wallet sync` applies, so both commands download the same
/// `GetBlockRange` windows.
fn split_into_batches(ranges: &[ScanRange], batch_size: u32) -> Vec<ScanRange> {
    ranges
        .iter()
        .flat_map(|r| {
            (0..).scan(r.clone(), move |acc, _| {
                if acc.is_empty() {
                    None
                } else if let Some((cur, next)) = acc.split_at(acc.block_range().start + batch_size)
                {
                    *acc = next;
                    Some(cur)
                } else {
                    let cur = acc.clone();
                    let end = acc.block_range().end;
                    *acc = ScanRange::from_parts(end..end, acc.priority());
                    Some(cur)
                }
            })
        })
        .collect()
}

/// Reads the single cached compact block at `height` from the local block
/// cache, if present. Purely local; no network access.
fn read_cached_block(
    db_cache: &FsBlockDb,
    height: BlockHeight,
) -> Result<Option<CompactBlock>, anyhow::Error> {
    let mut found = None;
    db_cache
        .with_blocks::<_, Infallible>(Some(height), Some(1), |block| {
            if block.height() == height {
                found = Some(block);
            }
            Ok(())
        })
        .map_err(|e| anyhow!("reading cached block {height}: {e:?}"))?;
    Ok(found)
}

/// The private (default) receive path: make the same block-download requests a
/// normal syncing wallet makes — subtree roots, chain tip, and an ordinary
/// full-range `GetBlockRange` over the scan gap — then, purely locally, decrypt
/// the advised block first for instant visibility and scan the rest of the gap
/// to completion. The indexer never learns which transaction or note is ours.
/// (This is not a byte-identical fingerprint: the downloads are front-loaded
/// rather than interleaved with scanning, and the transparent-UTXO refresh a
/// full sync performs is skipped — an indexer can still tell a receive from a
/// sync, it just never learns the advised note.)
///
/// Returns `Ok(Ok(()))` on success (the `ADVICE VERIFIED` line and timing are
/// printed here), `Ok(Err(reason))` for a protocol-level rejection, and `Err`
/// for a transport or database failure.
#[allow(clippy::too_many_arguments)]
async fn run_private_path<P: Parameters + Send + 'static>(
    params: &P,
    fsblockdb_root: &Path,
    db_cache: &mut FsBlockDb,
    db_data: &mut WalletDb<rusqlite::Connection, P, SystemClock, OsRng>,
    client: &mut CompactTxStreamerClient<Channel>,
    envelope: &crate::commands::advice::AdviceEnvelope,
    t0: Instant,
) -> Result<Result<(), String>, anyhow::Error> {
    // Same setup as `wallet sync`: subtree roots and chain tip.
    scan::update_subtree_roots(client, db_data).await?;
    let (tip_height, _tip_hash) = scan::update_chain_tip(client, db_data).await?;

    let advised_height = BlockHeight::from_u32(envelope.height);
    if advised_height > tip_height {
        return Ok(Err(format!(
            "advised height {advised_height} is above the chain tip {tip_height}"
        )));
    }

    let suggested = db_data.suggest_scan_ranges()?;
    let batches = split_into_batches(&suggested, BATCH_SIZE);
    if !batches
        .iter()
        .any(|r| r.block_range().contains(&advised_height))
    {
        return Ok(Err(format!(
            "advised height {advised_height} is not within the wallet's scan gap; the note is \
             already scanned or the wallet is out of sync — run `wallet sync`"
        )));
    }

    // Download the whole scan gap into the local cache using ordinary
    // GetBlockRange requests, identical to `wallet sync`. This is the only
    // network step; everything below is local.
    info!(
        "Downloading {} block range(s) over the scan gap (private full-range scan)",
        batches.len()
    );
    let mut downloaded: Vec<(ScanRange, ChainState, Vec<BlockMeta>)> = Vec::new();
    for batch in &batches {
        let block_meta =
            scan::download_blocks(client, fsblockdb_root, db_cache, batch, |_| false).await?;
        let chain_state = scan::download_chain_state(client, batch.block_range().start - 1).await?;
        downloaded.push((batch.clone(), chain_state, block_meta));
    }

    // Priority peek: decrypt only the advised block, from the cache, first.
    // This needs no note-commitment-tree state and issues no network request.
    let advised_block = read_cached_block(db_cache, advised_height)?.ok_or_else(|| {
        anyhow!("advised block {advised_height} missing from cache after download")
    })?;
    let ufvks = db_data.get_unified_full_viewing_keys()?;
    let peek: PeekOutcome = match peek_advised_output(params, ufvks, advised_block, envelope) {
        Ok(outcome) => outcome,
        Err(reason) => return Ok(Err(reason)),
    };
    let t_visible = t0.elapsed();
    println!(
        "ADVICE VERIFIED: received {} ZEC in tx {} at height {} (pool={}, index={})",
        format_zec(peek.value),
        envelope.txid,
        peek.mined_height,
        peek.pool,
        peek.index,
    );
    println!(
        "timing: time-to-first-visibility {t_visible:?} (advice in hand to advised note \
         decrypted; full-range block download + local peek, no GetTransaction)"
    );

    // Dual-rail completeness: scan the whole gap so no other payment is missed,
    // exactly as a normal sync finishing (the advised note is durably stored,
    // with its witness, here). A continuity error — a reorg, or the birthday
    // boundary on a freshly restored wallet — is recovered from with the same
    // `scan::rewind` machinery `wallet sync` uses, rather than aborting.
    //
    // Common case: the front-loaded blocks scan cleanly with no re-download, so
    // the indexer sees a single pass over the gap. A rewind is rare and only
    // then re-requests the affected ranges (a small, edge-case-only deviation).
    let mut recovered = false;
    let mut deletions = Vec::new();
    for (batch, chain_state, block_meta) in &downloaded {
        match scan_cached_blocks(
            params,
            db_cache,
            db_data,
            batch.block_range().start,
            chain_state,
            batch.len(),
        ) {
            Ok(_) => deletions.push(scan::delete_cached_blocks(
                fsblockdb_root,
                block_meta.clone(),
            )),
            Err(ChainError::Scan(err)) if err.is_continuity_error() => {
                let rewind_height = err.at_height().saturating_sub(scan::REORG_REWIND_MARGIN);
                scan::rewind(
                    db_data,
                    db_cache,
                    fsblockdb_root,
                    err.at_height(),
                    rewind_height,
                    tip_height,
                )?;
                recovered = true;
                break;
            }
            Err(e) => return Err(anyhow!("{:?}", e)),
        }
    }
    for deletion in deletions {
        deletion.await?;
    }

    // After a rewind the front-loaded cache/ranges are stale, so finish the gap
    // the way `wallet sync` does: re-suggest, re-download and re-scan until it
    // is clear, handling any further continuity errors the same way.
    let mut rewinds = 0u32;
    while recovered {
        rewinds += 1;
        if rewinds > 50 {
            return Err(anyhow!(
                "scan did not converge after 50 rewinds; run `wallet sync` to recover"
            ));
        }
        recovered = false;
        let ranges = db_data.suggest_scan_ranges()?;
        let mut dels = Vec::new();
        for range in split_into_batches(&ranges, BATCH_SIZE) {
            let block_meta =
                scan::download_blocks(client, fsblockdb_root, db_cache, &range, |_| false).await?;
            let chain_state =
                scan::download_chain_state(client, range.block_range().start - 1).await?;
            match scan_cached_blocks(
                params,
                db_cache,
                db_data,
                range.block_range().start,
                &chain_state,
                range.len(),
            ) {
                Ok(_) => dels.push(scan::delete_cached_blocks(fsblockdb_root, block_meta)),
                Err(ChainError::Scan(err)) if err.is_continuity_error() => {
                    let rewind_height = err.at_height().saturating_sub(scan::REORG_REWIND_MARGIN);
                    scan::rewind(
                        db_data,
                        db_cache,
                        fsblockdb_root,
                        err.at_height(),
                        rewind_height,
                        tip_height,
                    )?;
                    recovered = true;
                    break;
                }
                Err(e) => return Err(anyhow!("{:?}", e)),
            }
        }
        for deletion in dels {
            deletion.await?;
        }
    }
    println!("full sync completed: scanned the scan gap to the chain tip");

    Ok(Ok(()))
}

/// The `--fast-sync` receive path: fetch only the advised transaction with
/// `GetTransaction` and run a single targeted trial decryption. Lower privacy —
/// the advised txid is revealed to the indexer — and no full scan is performed.
async fn run_fast_path<P: Parameters>(
    params: &P,
    db_data: &mut WalletDb<rusqlite::Connection, P, SystemClock, OsRng>,
    client: &mut CompactTxStreamerClient<Channel>,
    envelope: &crate::commands::advice::AdviceEnvelope,
    t0: Instant,
) -> Result<Result<(), String>, anyhow::Error> {
    let (tip_height, _tip_hash) = scan::update_chain_tip(client, db_data).await?;

    let outcome = match verify_advice(params, db_data, client, tip_height, envelope).await? {
        Ok(outcome) => outcome,
        Err(reason) => return Ok(Err(reason)),
    };

    let t_total = t0.elapsed();
    println!(
        "ADVICE VERIFIED: received {} ZEC in tx {} at height {} (pool={}, index={})",
        format_zec(outcome.value),
        envelope.txid,
        outcome.mined_height,
        outcome.pool,
        outcome.index,
    );
    println!(
        "timing: total {:?}, tx fetch {:?}, decrypt+store {:?}",
        t_total, outcome.fetch_time, outcome.decrypt_time
    );
    Ok(Ok(()))
}

impl Command {
    pub(crate) async fn run(self, wallet_dir: Option<String>) -> Result<(), anyhow::Error> {
        let params = get_wallet_network(wallet_dir.as_ref())?;
        let (fsblockdb_root, db_data) = get_db_paths(wallet_dir.as_ref());
        let fsblockdb_root = fsblockdb_root.as_path();
        let mut db_data = WalletDb::for_path(db_data, params, SystemClock, OsRng)?;

        // The peers file (in the wallet dir) supplies the sender's stored
        // identity key, for envelope verification, and the subkey index this
        // relationship was paired with, for signing acks. An explicit wallet
        // dir is required, like `advice send`: falling back to the default
        // wallet dir would silently drop signature verification.
        let axion_dir = store::require_wallet_dir(wallet_dir.as_ref())?;
        let peer = store::load_peers(&axion_dir)?.remove(&self.from);
        let stored_pubkey = peer.as_ref().map(|p| p.pubkey.clone());

        // Derive the ack signing key up front so a wrong age identity file
        // fails before the sender is made to wait. The subkey index recorded
        // at pairing time wins over the command-line one.
        let ack_sk = match &self.identity {
            Some(identity_file) => {
                let index = peer.as_ref().and_then(|p| p.my_index).unwrap_or(self.index);
                Some(identity::wallet_signing_key(
                    wallet_dir.as_ref(),
                    identity_file,
                    index,
                )?)
            }
            None => {
                println!(
                    "no --identity given; advice will not be acknowledged (no address ratchet)"
                );
                None
            }
        };

        // Connect to SimpleX first so no advice message is missed.
        let mut simplex = SimplexClient::connect(&self.ws).await?;
        info!(
            "Waiting up to {}s for an advice message from {}",
            self.timeout, self.from
        );
        // Unrelated chatter from the contact must not abort the wait; only a
        // message that claims to be advice is validated strictly (and rejected
        // hard on failure). Skipped messages are debug-logged inside
        // wait_message_of_type, never at info: bodies can carry payment
        // metadata that should not land in default-level logs.
        let deadline = Instant::now() + Duration::from_secs(self.timeout);
        let envelope =
            match wait_message_of_type(&mut simplex, &self.from, &["advice"], deadline).await? {
                Some((_, text)) => {
                    debug!("Received advice message from {}", self.from);
                    // A malformed envelope gets no invalid-ack: its txid may not
                    // even be well-formed hex, and the ack signature covers it.
                    validate_envelope(&text).map_err(reject)?
                }
                None => {
                    return Err(anyhow!(
                        "timed out waiting for an advice message from {}",
                        self.from
                    ));
                }
            };

        // Envelope signature policy: a signature that fails against the key
        // stored at pairing time is a hard rejection; an unverifiable or
        // missing signature is only warned about (chain verification governs)
        // — but the degraded authenticity is printed on stdout so scripts can
        // tell the cases apart.
        let auth = match check_envelope_signature(&envelope, stored_pubkey.as_deref()) {
            Ok(auth) => auth,
            Err(e) => {
                send_invalid_ack(
                    &mut simplex,
                    &axion_dir,
                    &self.from,
                    ack_sk.as_ref(),
                    &envelope.txid,
                )
                .await;
                return Err(reject(e));
            }
        };
        match auth {
            EnvelopeAuth::Authenticated => {}
            EnvelopeAuth::Unverifiable => {
                println!("note: envelope signed but unverifiable (no stored identity key)")
            }
            EnvelopeAuth::Unauthenticated => {
                println!("note: envelope UNAUTHENTICATED (no signature); chain verification only")
            }
        }

        // Time-to-first-visibility is measured from advice-in-hand (the
        // validated envelope) to the `ADVICE VERIFIED` line printed by the
        // selected path.
        let t0 = Instant::now();

        let mut client = self.connection.connect(params, wallet_dir.as_ref()).await?;

        let path_result = if self.fast_sync {
            warn!(
                "--fast-sync: fetching only the advised transaction; its txid is revealed to the \
                 indexer and no full scan is performed"
            );
            run_fast_path(&params, &mut db_data, &mut client, &envelope, t0).await?
        } else {
            let mut db_cache = FsBlockDb::for_path(fsblockdb_root).map_err(error::Error::from)?;
            run_private_path(
                &params,
                fsblockdb_root,
                &mut db_cache,
                &mut db_data,
                &mut client,
                &envelope,
                t0,
            )
            .await?
        };

        if let Err(reason) = path_result {
            send_invalid_ack(
                &mut simplex,
                &axion_dir,
                &self.from,
                ack_sk.as_ref(),
                &envelope.txid,
            )
            .await;
            return Err(reject(reason));
        }

        // Acknowledge with the next fresh diversified address, ratcheting the
        // address the sender pays (spec 1.3.3).
        if let Some(sk) = &ack_sk {
            let next_address = mint_next_address(&params, &mut db_data)?;
            let counter = store::next_outgoing_counter(&axion_dir, &self.from)?;
            let ack = build_signed_ack(
                sk,
                &envelope.txid,
                "accepted",
                counter,
                next_address.clone(),
            )?;
            simplex
                .send_text(&self.from, &serde_json::to_string(&ack)?)
                .await?;
            println!("ack sent: accepted, next address {next_address}");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{BATCH_SIZE, split_into_batches};
    use zcash_client_backend::data_api::scanning::{ScanPriority, ScanRange};
    use zcash_protocol::consensus::BlockHeight;

    fn range(start: u32, end: u32) -> ScanRange {
        ScanRange::from_parts(
            BlockHeight::from_u32(start)..BlockHeight::from_u32(end),
            ScanPriority::ChainTip,
        )
    }

    #[test]
    fn batching_preserves_coverage_and_advised_membership() {
        // A gap larger than one batch splits into consecutive batches that
        // together cover the whole range with no gaps or overlaps.
        let gap = range(100, 100 + BATCH_SIZE + 500);
        let batches = split_into_batches(std::slice::from_ref(&gap), BATCH_SIZE);
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].block_range().start, BlockHeight::from_u32(100));
        assert_eq!(
            batches[0].block_range().end,
            BlockHeight::from_u32(100 + BATCH_SIZE)
        );
        assert_eq!(
            batches[1].block_range().start,
            BlockHeight::from_u32(100 + BATCH_SIZE)
        );
        assert_eq!(
            batches[1].block_range().end,
            BlockHeight::from_u32(100 + BATCH_SIZE + 500)
        );

        // The batch containing an advised height near the end of the gap is
        // located correctly — this is what the priority peek keys off.
        let advised = BlockHeight::from_u32(100 + BATCH_SIZE + 250);
        let idx = batches
            .iter()
            .position(|r| r.block_range().contains(&advised));
        assert_eq!(idx, Some(1));
    }

    #[test]
    fn small_gap_is_a_single_batch() {
        let gap = range(200, 260);
        let batches = split_into_batches(std::slice::from_ref(&gap), BATCH_SIZE);
        assert_eq!(batches.len(), 1);
        assert!(
            batches[0]
                .block_range()
                .contains(&BlockHeight::from_u32(230))
        );
    }
}
