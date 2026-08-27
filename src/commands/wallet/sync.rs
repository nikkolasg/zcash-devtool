use std::path::Path;

use anyhow::anyhow;
use clap::Args;
use futures_util::TryStreamExt;
use rand::rngs::OsRng;

use tonic::transport::Channel;
use tracing::{debug, info, warn};
use zcash_client_backend::{
    data_api::{
        WalletRead, WalletWrite,
        chain::{ChainState, error::Error as ChainError, scan_cached_blocks},
        scanning::{ScanPriority, ScanRange},
        wallet::ConfirmationsPolicy,
    },
    proto::service::{self, compact_tx_streamer_client::CompactTxStreamerClient},
};
use zcash_client_sqlite::{FsBlockDb, WalletDb, chain::BlockMeta, util::SystemClock};
use zcash_protocol::consensus::{BlockHeight, Parameters};

use crate::{
    ShutdownListener, config::get_wallet_network, data::get_db_paths, error, helpers::scan,
    remote::ConnectionArgs,
};

#[cfg(feature = "transparent-inputs")]
use {
    ::transparent::{
        address::Script,
        bundle::{OutPoint, TxOut},
    },
    zcash_client_backend::wallet::WalletTransparentOutput,
    zcash_client_sqlite::AccountUuid,
    zcash_keys::encoding::AddressCodec,
    zcash_protocol::value::Zatoshis,
    zcash_script::script,
};

#[cfg(feature = "tui")]
use zcash_protocol::consensus::NetworkUpgrade;

#[cfg(feature = "tui")]
use crate::tui::Tui;

#[cfg(feature = "tui")]
mod defrag;

const BATCH_SIZE: u32 = 10_000;

// Options accepted for the `sync` command
#[derive(Debug, Args)]
pub(crate) struct Command {
    #[command(flatten)]
    connection: ConnectionArgs,

    #[cfg(feature = "tui")]
    #[arg(long)]
    pub(crate) defrag: bool,
}

impl Command {
    pub(crate) async fn run(
        self,
        mut shutdown: ShutdownListener,
        wallet_dir: Option<String>,
        #[cfg(feature = "tui")] tui: Tui,
    ) -> Result<(), anyhow::Error> {
        let params = get_wallet_network(wallet_dir.as_ref())?;

        let (fsblockdb_root, db_data) = get_db_paths(wallet_dir.as_ref());
        let fsblockdb_root = fsblockdb_root.as_path();
        let mut db_cache = FsBlockDb::for_path(fsblockdb_root).map_err(error::Error::from)?;
        let mut db_data = WalletDb::for_path(db_data, params, SystemClock, OsRng)?;
        let mut client = self.connection.connect(params, wallet_dir.as_ref()).await?;

        #[cfg(feature = "tui")]
        let wallet_birthday = db_data
            .get_wallet_birthday()?
            .unwrap_or_else(|| params.activation_height(NetworkUpgrade::Sapling).unwrap());

        #[cfg(feature = "tui")]
        let tui_handle = if self.defrag {
            let mut app = defrag::App::new(shutdown.tui_quit_signal(), wallet_birthday);
            let handle = app.handle();
            tokio::spawn(async move {
                if let Err(e) = app.run(tui).await {
                    tracing::error!("Error while running TUI: {e}");
                }
            });
            Some(handle)
        } else {
            None
        };

        // 1) Download note commitment tree data from lightwalletd
        // 2) Pass the commitment tree data to the database.
        scan::update_subtree_roots(&mut client, &mut db_data).await?;

        #[allow(clippy::too_many_arguments)]
        async fn running<P: Parameters + Send + 'static>(
            shutdown: &mut ShutdownListener,
            client: &mut CompactTxStreamerClient<Channel>,
            params: &P,
            fsblockdb_root: &Path,
            db_cache: &mut FsBlockDb,
            db_data: &mut WalletDb<rusqlite::Connection, P, SystemClock, OsRng>,
            #[cfg(feature = "tui")] tui_handle: Option<&defrag::AppHandle>,
        ) -> Result<bool, anyhow::Error> {
            // 3) Download chain tip metadata from lightwalletd
            // 4) Notify the wallet of the updated chain tip.
            let (_chain_tip, tip_hash) = scan::update_chain_tip(client, db_data).await?;

            // The wallet's `update_chain_tip` intentionally does nothing when the
            // reported tip is below our maximum scanned height: it leaves reorg
            // detection to the scanner's block-continuity check. But when we are
            // already fully synced there are no ranges left to scan, so a reorg
            // that shortens the chain below our scanned height would go unnoticed
            // until the chain grew back past it (as zecd, which is reactive-only,
            // also would). Detect that case here — but only for a *genuine* reorg.
            //
            // A reported tip below our scanned height is either a real reorg (the
            // chain was rolled back) or merely a node that is lagging / briefly
            // disagreeing (common when a light client hops between servers during
            // a reorg). Distinguish them by comparing the node's tip hash against
            // our stored hash at that height: a bare height comparison rewinds on
            // a lagging node too, which ratchets the wallet backwards. Only rewind
            // when the hashes actually differ (or we no longer hold that block).
            if let Some(max_scanned) = db_data.block_max_scanned()?.map(|b| b.block_height()) {
                let diverged = _chain_tip < max_scanned
                    && db_data.block_metadata(_chain_tip)?.map(|m| m.block_hash())
                        != Some(tip_hash);
                if diverged {
                    let rewind_height = _chain_tip.saturating_sub(scan::REORG_REWIND_MARGIN);
                    warn!(
                        "Chain tip {} diverges from our history (max scanned {}); reorg detected, rewinding to {}",
                        _chain_tip, max_scanned, rewind_height,
                    );
                    scan::rewind(
                        db_data,
                        db_cache,
                        fsblockdb_root,
                        _chain_tip,
                        rewind_height,
                        _chain_tip,
                    )?;
                }
            }
            #[cfg(feature = "tui")]
            if let Some(handle) = tui_handle {
                handle.set_wallet_summary(
                    db_data.get_wallet_summary(ConfirmationsPolicy::default())?,
                );
            }

            // Refresh UTXOs for the accounts in the wallet.
            #[cfg(feature = "transparent-inputs")]
            for account_id in db_data.get_account_ids()? {
                info!(
                    "Refreshing UTXOs for {:?} from height {}",
                    account_id,
                    BlockHeight::from(0),
                );
                refresh_utxos(params, client, db_data, account_id, BlockHeight::from(0)).await?;
            }

            // 5) Get the suggested scan ranges from the wallet database
            info!("Fetching scan ranges");
            let mut scan_ranges = db_data.suggest_scan_ranges()?;
            info!("Fetched {} scan ranges", scan_ranges.len());
            #[cfg(feature = "tui")]
            if let Some(handle) = tui_handle {
                if handle.set_scan_ranges(&scan_ranges, _chain_tip) {
                    // TUI exited.
                    return Ok(false);
                }
            }
            if shutdown.requested() {
                return Ok(false);
            }

            // Store the handles to cached block deletions (which we spawn into separate
            // tasks to allow us to continue downloading and scanning other ranges).
            let mut block_deletions = vec![];

            // 6) Run the following loop until the wallet's view of the chain tip as of
            //    the previous wallet session is valid.
            loop {
                // If there is a range of blocks that needs to be verified, it will always
                // be returned as the first element of the vector of suggested ranges.
                match scan_ranges.first() {
                    Some(scan_range) if scan_range.priority() == ScanPriority::Verify => {
                        // Download the blocks in `scan_range` into the block source,
                        // overwriting any existing blocks in this range.
                        let block_meta = download_blocks(
                            client,
                            fsblockdb_root,
                            db_cache,
                            scan_range,
                            shutdown,
                            #[cfg(feature = "tui")]
                            tui_handle,
                        )
                        .await?;

                        if shutdown.requested() {
                            return Ok(false);
                        }

                        let chain_state =
                            scan::download_chain_state(client, scan_range.block_range().start - 1)
                                .await?;

                        // Scan the downloaded blocks and check for scanning errors that
                        // indicate the wallet's chain tip is out of sync with blockchain
                        // history.
                        let scan_ranges_updated = scan_blocks(
                            params,
                            fsblockdb_root,
                            db_cache,
                            db_data,
                            &chain_state,
                            scan_range,
                            #[cfg(feature = "tui")]
                            tui_handle,
                            _chain_tip,
                        )?;

                        // Delete the now-scanned blocks, because keeping the entire chain
                        // in CompactBlock files on disk is horrendous for the filesystem.
                        block_deletions
                            .push(scan::delete_cached_blocks(fsblockdb_root, block_meta));

                        if scan_ranges_updated {
                            // The suggested scan ranges have been updated, so we re-request.
                            scan_ranges = db_data.suggest_scan_ranges()?;
                            #[cfg(feature = "tui")]
                            if let Some(handle) = tui_handle {
                                if handle.set_scan_ranges(&scan_ranges, _chain_tip) {
                                    // TUI exited.
                                    return Ok(false);
                                }
                            }
                            if shutdown.requested() {
                                return Ok(false);
                            }
                        } else {
                            // At this point, the cache and scanned data are locally
                            // consistent (though not necessarily consistent with the
                            // latest chain tip - this would be discovered the next time
                            // this codepath is executed after new blocks are received) so
                            // we can break out of the loop.
                            break;
                        }
                    }
                    _ => {
                        // Nothing to verify; break out of the loop
                        break;
                    }
                }
            }

            // 7) Loop over the remaining suggested scan ranges, retrieving the requested data
            //    and calling `scan_cached_blocks` on each range.
            let scan_ranges = db_data.suggest_scan_ranges()?;
            debug!("Suggested ranges: {:?}", scan_ranges);
            #[cfg(feature = "tui")]
            if let Some(handle) = tui_handle {
                if handle.set_scan_ranges(&scan_ranges, _chain_tip) {
                    // TUI exited.
                    return Ok(false);
                }
            }
            if shutdown.requested() {
                return Ok(false);
            }
            for scan_range in scan_ranges.into_iter().flat_map(|r| {
                // Limit the number of blocks we download and scan at any one time.
                (0..).scan(r, |acc, _| {
                    if acc.is_empty() {
                        None
                    } else if let Some((cur, next)) =
                        acc.split_at(acc.block_range().start + BATCH_SIZE)
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
            }) {
                // Download the blocks in `scan_range` into the block source.
                let block_meta = download_blocks(
                    client,
                    fsblockdb_root,
                    db_cache,
                    &scan_range,
                    shutdown,
                    #[cfg(feature = "tui")]
                    tui_handle,
                )
                .await?;

                if shutdown.requested() {
                    return Ok(false);
                }

                let chain_state =
                    scan::download_chain_state(client, scan_range.block_range().start - 1).await?;

                // Scan the downloaded blocks.
                let scan_ranges_updated = scan_blocks(
                    params,
                    fsblockdb_root,
                    db_cache,
                    db_data,
                    &chain_state,
                    &scan_range,
                    #[cfg(feature = "tui")]
                    tui_handle,
                    _chain_tip,
                )?;

                // Delete the now-scanned blocks.
                block_deletions.push(scan::delete_cached_blocks(fsblockdb_root, block_meta));

                if scan_ranges_updated || shutdown.requested() {
                    // The suggested scan ranges have been updated (either due to a continuity
                    // error or because a higher priority range has been added).
                    info!("Waiting for cached blocks to be deleted...");
                    for deletion in block_deletions {
                        deletion.await?;
                    }
                    return Ok(!shutdown.requested());
                }
            }

            info!("Waiting for cached blocks to be deleted...");
            for deletion in block_deletions {
                deletion.await?;
            }
            Ok(false)
        }

        while running(
            &mut shutdown,
            &mut client,
            &params,
            fsblockdb_root,
            &mut db_cache,
            &mut db_data,
            #[cfg(feature = "tui")]
            tui_handle.as_ref(),
        )
        .await?
        {}

        Ok(())
    }
}

/// Downloads the blocks in `scan_range` into the cache via the shared
/// [`scan::download_blocks`], layering on this command's TUI progress reporting
/// and cooperative-shutdown handling.
async fn download_blocks(
    client: &mut CompactTxStreamerClient<Channel>,
    fsblockdb_root: &Path,
    db_cache: &FsBlockDb,
    scan_range: &ScanRange,
    shutdown: &mut ShutdownListener,
    #[cfg(feature = "tui")] tui_handle: Option<&defrag::AppHandle>,
) -> Result<Vec<BlockMeta>, anyhow::Error> {
    #[cfg(feature = "tui")]
    if let Some(handle) = tui_handle {
        handle.set_fetching_range(Some(scan_range.block_range().clone()));
    }
    let block_meta = scan::download_blocks(client, fsblockdb_root, db_cache, scan_range, |meta| {
        #[cfg(feature = "tui")]
        if let Some(handle) = tui_handle {
            handle.set_fetched(meta.height);
        }
        #[cfg(not(feature = "tui"))]
        let _ = meta;
        // Stop fetching blocks; we will exit once we return.
        shutdown.requested()
    })
    .await?;

    #[cfg(feature = "tui")]
    if let Some(handle) = tui_handle {
        handle.set_fetching_range(None);
    }
    Ok(block_meta)
}

/// Scans the given block range and checks for scanning errors that indicate the wallet's
/// chain tip is out of sync with blockchain history.
///
/// Returns `true` if scanning these blocks materially changed the suggested scan ranges.
#[allow(clippy::too_many_arguments)]
fn scan_blocks<P: Parameters + Send + 'static>(
    params: &P,
    fsblockdb_root: &Path,
    db_cache: &mut FsBlockDb,
    db_data: &mut WalletDb<rusqlite::Connection, P, SystemClock, OsRng>,
    initial_chain_state: &ChainState,
    scan_range: &ScanRange,
    #[cfg(feature = "tui")] tui_handle: Option<&defrag::AppHandle>,
    chain_tip: BlockHeight,
) -> Result<bool, anyhow::Error> {
    info!("Scanning {}", scan_range);
    #[cfg(feature = "tui")]
    if let Some(handle) = tui_handle {
        handle.set_scanning_range(Some(scan_range.block_range().clone()));
    }
    let scan_result = scan_cached_blocks(
        params,
        db_cache,
        db_data,
        scan_range.block_range().start,
        initial_chain_state,
        scan_range.len(),
    );
    #[cfg(feature = "tui")]
    if let Some(handle) = tui_handle {
        handle.set_scanning_range(None);
        handle.set_wallet_summary(db_data.get_wallet_summary(ConfirmationsPolicy::default())?);
    }

    match scan_result {
        Err(ChainError::Scan(err)) if err.is_continuity_error() => {
            // Pick a height to rewind to, which must be at least one block before the
            // height at which the error occurred, but may be an earlier height determined
            // based on heuristics such as the platform, available bandwidth, size of
            // recent CompactBlocks, etc.
            let rewind_height = err.at_height().saturating_sub(scan::REORG_REWIND_MARGIN);
            info!(
                "Chain reorg detected at {}, rewinding to {} (scan error: {:?})",
                err.at_height(),
                rewind_height,
                err,
            );

            scan::rewind(
                db_data,
                db_cache,
                fsblockdb_root,
                err.at_height(),
                rewind_height,
                chain_tip,
            )?;

            // The database was truncated, invalidating prior suggested ranges.
            Ok(true)
        }
        Ok(_) => {
            if let Some(summary) = db_data.get_wallet_summary(ConfirmationsPolicy::MIN)? {
                info!(
                    "Scan complete for range {}; progress is {}/{}",
                    scan_range,
                    summary.progress().scan().numerator()
                        + summary.progress().recovery().map_or(0, |p| *p.numerator()),
                    summary.progress().scan().denominator()
                        + summary
                            .progress()
                            .recovery()
                            .map_or(0, |p| *p.denominator()),
                )
            }

            // If scanning these blocks caused a suggested range to be added that has a
            // higher priority than the current range, invalidate the current ranges.
            let latest_ranges = db_data.suggest_scan_ranges()?;
            #[cfg(feature = "tui")]
            if let Some(handle) = tui_handle {
                if handle.set_scan_ranges(&latest_ranges, chain_tip) {
                    // TUI exited.
                    return Ok(false);
                }
            }

            Ok(if let Some(range) = latest_ranges.first() {
                range.priority() > scan_range.priority()
            } else {
                false
            })
        }
        Err(e) => Err(anyhow!("{:?}", e)),
    }
}

/// Refreshes the given account's view of UTXOs that exist starting at the given height.
///
/// ## Note about UTXO tracking
///
/// (Extracted from [a comment in the Android SDK].)
///
/// We no longer clear UTXOs here, as `WalletDb::put_received_transparent_utxo` now uses
/// an upsert instead of an insert. This means that now-spent UTXOs would previously have
/// been deleted, but now are left in the database (like shielded notes).
///
/// Due to the fact that the `lightwalletd` query only returns _current_ UTXOs, we don't
/// learn about recently-spent UTXOs here, so the transparent balance does not get updated
/// here.
///
/// Instead, when a received shielded note is "enhanced" by downloading the full
/// transaction, we mark any UTXOs spent in that transaction as spent in the database.
/// This relies on two current properties:
/// - UTXOs are only ever spent in shielding transactions.
/// - At least one shielded note from each shielding transaction is always enhanced.
///
/// However, for greater reliability, we may want to alter the Data Access API to support
/// "inferring spentness" from what is _not_ returned as a UTXO, or alternatively fetch
/// TXOs from `lightwalletd` instead of just UTXOs.
///
/// [a comment in the Android SDK]: https://github.com/Electric-Coin-Company/zcash-android-wallet-sdk/blob/855204fc8ae4057fdac939f98df4aa38c8e662f1/sdk-lib/src/main/java/cash/z/ecc/android/sdk/block/processor/CompactBlockProcessor.kt#L979-L991
#[cfg(feature = "transparent-inputs")]
async fn refresh_utxos<P: Parameters>(
    params: &P,
    client: &mut CompactTxStreamerClient<Channel>,
    db_data: &mut WalletDb<rusqlite::Connection, P, SystemClock, OsRng>,
    account_id: AccountUuid,
    start_height: BlockHeight,
) -> Result<(), anyhow::Error> {
    let addresses = db_data
        .get_transparent_receivers(account_id, true, true)?
        .into_keys()
        .map(|addr| addr.encode(params))
        .collect::<Vec<_>>();

    if addresses.is_empty() {
        return Ok(());
    }

    let request = service::GetAddressUtxosArg {
        addresses,
        start_height: start_height.into(),
        max_entries: 0,
    };

    if request.addresses.is_empty() {
        info!("{:?} has no transparent receivers", account_id);
    } else {
        client
            .get_address_utxos_stream(request)
            .await?
            .into_inner()
            .map_err(anyhow::Error::from)
            .and_then(|reply| async move {
                WalletTransparentOutput::from_parts(
                    OutPoint::new(reply.txid[..].try_into()?, reply.index.try_into()?),
                    TxOut::new(
                        Zatoshis::from_nonnegative_i64(reply.value_zat)?,
                        Script(script::Code(reply.script)),
                    ),
                    Some(BlockHeight::from(u32::try_from(reply.height)?)),
                    // A UTXO fetched from lightwalletd carries no wallet-account
                    // context; the wallet associates it on store.
                    None,
                    None,
                    None,
                )
                .ok_or(anyhow!(
                    "Received UTXO that doesn't correspond to a valid P2PKH or P2SH address"
                ))
            })
            .try_for_each(|output| {
                let res = db_data.put_received_transparent_utxo(&output).map(|_| ());
                async move { res.map_err(anyhow::Error::from) }
            })
            .await?;
    }

    Ok(())
}
