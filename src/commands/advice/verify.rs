//! Shared receive-side verification of advice envelopes: fetch the one
//! advised transaction, run a targeted trial decryption, and confirm with the
//! wallet's own viewing keys that it pays this wallet. Used by both
//! `advice receive` and `advice recover`.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use tonic::transport::Channel;
use tracing::{info, warn};
use zcash_client_backend::{
    TransferType,
    data_api::{WalletWrite, wallet::decrypt_and_store_transaction},
    decrypt_transaction,
    proto::compact_formats::CompactBlock,
    proto::service::compact_tx_streamer_client::CompactTxStreamerClient,
    scanning::{Nullifiers, ScanningKeys, scan_block},
};
use zcash_client_sqlite::AccountUuid;
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_protocol::{ShieldedPool, consensus::BlockHeight, consensus::Parameters, value::COIN};

use crate::{
    commands::advice::{AdviceEnvelope, check_hex, check_kind, check_v1, parse_txid},
    helpers::tx_fetch::fetch_transaction,
};

pub(crate) fn validate_envelope(text: &str) -> Result<AdviceEnvelope, String> {
    let envelope: AdviceEnvelope =
        serde_json::from_str(text).map_err(|e| format!("invalid JSON: {e}"))?;
    check_v1(envelope.v)?;
    check_kind(&envelope.kind, "advice")?;
    check_hex("txid", &envelope.txid, 32)?;
    if envelope.height == 0 {
        return Err("height must be positive".to_string());
    }
    if !matches!(envelope.pool.as_str(), "orchard" | "sapling" | "ironwood") {
        return Err(format!("unknown pool {:?}", envelope.pool));
    }
    if let Some(sig) = &envelope.sig {
        check_hex("sig", sig, 64)?;
    }
    Ok(envelope)
}

/// Picks the incoming output the envelope advertised, falling back to the first
/// incoming output (with a warning) when the advertised `(pool, index)` is not
/// among them — a signed envelope can still carry a miscounted index. Returns
/// the chosen `(pool, index)` and the total incoming value, summed over all
/// incoming outputs regardless of which one was advertised.
fn select_output(
    incoming: &[(&'static str, usize, u64)],
    envelope: &AdviceEnvelope,
) -> (&'static str, usize, u64) {
    let advertised = (envelope.pool.as_str(), envelope.output_index as usize);
    let (pool, index, _) = incoming
        .iter()
        .find(|(pool, index, _)| (*pool, *index) == advertised)
        .unwrap_or_else(|| {
            warn!(
                "advertised output (pool={}, index={}) is not among the incoming outputs; \
                 accepting anyway (sender may have counted differently)",
                envelope.pool, envelope.output_index
            );
            &incoming[0]
        });
    let value: u64 = incoming.iter().map(|(_, _, value)| value).sum();
    (pool, *index, value)
}

pub(crate) fn pool_name(pool: ShieldedPool) -> &'static str {
    match pool {
        ShieldedPool::Sapling => "sapling",
        ShieldedPool::Orchard => "orchard",
        ShieldedPool::Ironwood => "ironwood",
    }
}

pub(crate) fn format_zec(zatoshis: u64) -> String {
    format!("{}.{:08}", zatoshis / COIN, zatoshis % COIN)
}

/// The successful outcome of verifying one advice envelope.
pub(crate) struct AdviceOutcome {
    /// Total value (in zatoshis) of the incoming outputs of the advised tx.
    pub(crate) value: u64,
    pub(crate) pool: &'static str,
    pub(crate) index: usize,
    pub(crate) mined_height: BlockHeight,
    pub(crate) fetch_time: Duration,
    pub(crate) decrypt_time: Duration,
}

/// Verifies one advice envelope against the chain. The outer error is a
/// transport or database failure; the inner `Err(String)` is a protocol-level
/// rejection of this specific advice (callers decide whether that aborts, as
/// in `advice receive`, or merely skips the advice, as in `advice recover`).
pub(crate) async fn verify_advice<P, DbT>(
    params: &P,
    db_data: &mut DbT,
    client: &mut CompactTxStreamerClient<Channel>,
    tip_height: BlockHeight,
    envelope: &AdviceEnvelope,
) -> Result<Result<AdviceOutcome, String>, anyhow::Error>
where
    P: Parameters,
    DbT: WalletWrite,
    DbT::Error: std::error::Error + Send + Sync + 'static,
{
    let txid = match parse_txid(&envelope.txid) {
        Ok(txid) => txid,
        Err(e) => return Ok(Err(e.to_string())),
    };

    info!("Fetching the one advised transaction {}", envelope.txid);
    let fetch_start = Instant::now();
    let fetched = fetch_transaction(client, params, tip_height, txid).await?;
    let fetch_time = fetch_start.elapsed();

    let (tx, mined_height) = match fetched {
        Some(fetched) => fetched,
        None => return Ok(Err("transaction not found".to_string())),
    };
    if tx.txid() != txid {
        return Ok(Err("server returned a different transaction".to_string()));
    }
    let mined_height = match mined_height {
        Some(height) => height,
        None => return Ok(Err("transaction is not mined".to_string())),
    };
    if u32::from(mined_height) != envelope.height {
        return Ok(Err(format!(
            "advertised height {} does not match mined height {}",
            envelope.height, mined_height
        )));
    }

    info!(
        "Running one targeted trial decryption for tx {} (no chain scan)",
        envelope.txid
    );
    let decrypt_start = Instant::now();
    decrypt_and_store_transaction(params, db_data, &tx, Some(mined_height))?;
    let decrypt_time = decrypt_start.elapsed();

    // Verify with this wallet's own viewing keys that the transaction
    // actually pays us, independently of what the sender claimed.
    let ufvks = db_data.get_unified_full_viewing_keys()?;
    let decrypted = decrypt_transaction(params, Some(mined_height), Some(tip_height), &tx, &ufvks);

    let mut incoming: Vec<(&'static str, usize, u64)> = Vec::new();
    for out in decrypted.sapling_outputs() {
        if out.transfer_type() == TransferType::Incoming {
            incoming.push(("sapling", out.index(), u64::from(out.note_value())));
        }
    }
    for out in decrypted
        .orchard_outputs()
        .iter()
        .chain(decrypted.ironwood_outputs())
    {
        if out.transfer_type() == TransferType::Incoming {
            incoming.push((
                pool_name(out.value_pool()),
                out.index(),
                out.note().0.value().inner(),
            ));
        }
    }

    if incoming.is_empty() {
        return Ok(Err("transaction pays this wallet nothing".to_string()));
    }
    let (pool, index, value) = select_output(&incoming, envelope);

    Ok(Ok(AdviceOutcome {
        value,
        pool,
        index,
        mined_height,
        fetch_time,
        decrypt_time,
    }))
}

/// The successful outcome of the priority peek: a purely local trial
/// decryption of a single cached compact block confirming that the advised
/// output pays this wallet.
pub(crate) struct PeekOutcome {
    /// Total value (in zatoshis) of the incoming outputs of the advised tx.
    pub(crate) value: u64,
    pub(crate) pool: &'static str,
    pub(crate) index: usize,
    pub(crate) mined_height: BlockHeight,
}

/// Trial-decrypts a single cached compact block (the advised block) with this
/// wallet's viewing keys, confirming that the advised transaction pays us.
///
/// This is the "priority peek": it reuses the same `scan_block` decryption
/// machinery `scan_cached_blocks` runs internally, but on one already-cached
/// block only, so it needs no note-commitment-tree state and therefore issues
/// no network request. The advised note is durably stored (with its witness)
/// by the full-range scan that runs immediately afterwards.
///
/// `Err(String)` is a protocol-level rejection of this advice (the block does
/// not decrypt to a payment to this wallet at the advertised output).
pub(crate) fn peek_advised_output<P: Parameters + Send + 'static>(
    params: &P,
    ufvks: HashMap<AccountUuid, UnifiedFullViewingKey>,
    block: CompactBlock,
    envelope: &AdviceEnvelope,
) -> Result<PeekOutcome, String> {
    let advised_txid = parse_txid(&envelope.txid).map_err(|e| e.to_string())?;
    let block_height = block.height();
    if u32::from(block_height) != envelope.height {
        return Err(format!(
            "advised height {} does not match the cached block height {}",
            envelope.height, block_height
        ));
    }

    // `scan_block` returns only the outputs that decrypt to our viewing keys.
    // No prior block metadata or nullifiers are needed: we are confirming
    // receipt of a note, not reconciling spends or witnesses (the full scan
    // does that).
    let scanning_keys = ScanningKeys::from_account_ufvks(ufvks);
    let scanned = scan_block(params, block, &scanning_keys, &Nullifiers::empty(), None)
        .map_err(|e| format!("failed to scan advised block: {e:?}"))?;

    let Some(wtx) = scanned
        .transactions()
        .iter()
        .find(|tx| tx.txid() == advised_txid)
    else {
        return Err(
            "advised transaction does not appear in its block, or pays this wallet nothing"
                .to_string(),
        );
    };

    let mut incoming: Vec<(&'static str, usize, u64)> = Vec::new();
    for out in wtx.sapling_outputs() {
        incoming.push(("sapling", out.index(), out.note().value().inner()));
    }
    for out in wtx.orchard_outputs() {
        incoming.push(("orchard", out.index(), out.note().0.value().inner()));
    }
    for out in wtx.ironwood_outputs() {
        incoming.push(("ironwood", out.index(), out.note().0.value().inner()));
    }

    if incoming.is_empty() {
        return Err("advised transaction pays this wallet nothing".to_string());
    }
    let (pool, index, value) = select_output(&incoming, envelope);

    Ok(PeekOutcome {
        value,
        pool,
        index,
        mined_height: block_height,
    })
}

#[cfg(test)]
mod tests {
    use super::validate_envelope;

    const TXID: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    fn envelope_json(v: u32, kind: &str, txid: &str, height: u32, pool: &str) -> String {
        format!(
            r#"{{"v":{v},"type":"{kind}","txid":"{txid}","height":{height},"pool":"{pool}","output_index":0}}"#
        )
    }

    #[test]
    fn accepts_valid_envelope() {
        let envelope =
            validate_envelope(&envelope_json(1, "advice", TXID, 100, "orchard")).unwrap();
        assert_eq!(envelope.txid, TXID);
        assert_eq!(envelope.height, 100);
    }

    #[test]
    fn validates_optional_envelope_signature() {
        let with_sig = |sig: &str| {
            format!(
                r#"{{"v":1,"type":"advice","txid":"{TXID}","height":100,"pool":"orchard","output_index":0,"sig":"{sig}"}}"#
            )
        };
        let envelope = validate_envelope(&with_sig(&"ab".repeat(64))).unwrap();
        assert_eq!(envelope.sig.as_deref(), Some("ab".repeat(64).as_str()));
        // Unsigned envelopes (the pre-signature format) still validate.
        assert_eq!(
            validate_envelope(&envelope_json(1, "advice", TXID, 100, "orchard"))
                .unwrap()
                .sig,
            None
        );
        assert!(validate_envelope(&with_sig("abcd")).is_err());
        assert!(validate_envelope(&with_sig(&"zz".repeat(64))).is_err());
    }

    #[test]
    fn rejects_invalid_envelopes() {
        assert!(validate_envelope("not json").is_err());
        assert!(validate_envelope(&envelope_json(2, "advice", TXID, 100, "orchard")).is_err());
        assert!(validate_envelope(&envelope_json(1, "other", TXID, 100, "orchard")).is_err());
        assert!(validate_envelope(&envelope_json(1, "advice", "abcd", 100, "orchard")).is_err());
        assert!(validate_envelope(&envelope_json(1, "advice", TXID, 0, "orchard")).is_err());
        assert!(validate_envelope(&envelope_json(1, "advice", TXID, 100, "transparent")).is_err());
    }
}
