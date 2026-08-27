//! Shared syncing primitives used by both `wallet sync` and `advice receive`:
//! updating the wallet's subtree roots and chain tip, downloading compact
//! blocks into the local `FsBlockDb` cache with an ordinary `GetBlockRange`,
//! fetching the chain state at a range boundary, and deleting scanned blocks.
//!
//! Hoisting these out of `wallet sync` lets `advice receive` issue the same
//! block-download requests a normal syncing wallet makes, so the indexer never
//! learns which transaction or note is the recipient's. It is not a
//! byte-identical fingerprint — `advice receive` front-loads the downloads and
//! skips the transparent-UTXO refresh a full sync performs — but the requests
//! that would reveal the advised note are identical to an ordinary scan of the
//! same gap.

use std::path::Path;

use anyhow::anyhow;
use futures_util::TryStreamExt;
use orchard::tree::MerkleHashOrchard;
use prost::Message;
use rand::rngs::OsRng;
use tokio::{fs::File, io::AsyncWriteExt, task::JoinHandle};
use tonic::{Code, transport::Channel};
use tracing::{error, info};
use zcash_client_backend::{
    data_api::{
        WalletCommitmentTrees, WalletWrite,
        chain::{ChainState, CommitmentTreeRoot},
        scanning::ScanRange,
    },
    proto::service::{self, BlockId, compact_tx_streamer_client::CompactTxStreamerClient},
};
use zcash_client_sqlite::{
    FsBlockDb, WalletDb, chain::BlockMeta, error::SqliteClientError, util::SystemClock,
};
use zcash_primitives::block::BlockHash;
use zcash_primitives::merkle_tree::HashSer;
use zcash_protocol::consensus::{BlockHeight, Parameters};

use crate::{
    data::{get_block_path, get_blocks_dir},
    error,
};

/// When a reorg (or a birthday-boundary continuity gap) is detected, rewind this
/// many blocks below the conflict before re-scanning, to give a margin for
/// re-crossing the actual fork height.
pub(crate) const REORG_REWIND_MARGIN: u32 = 10;

/// Fetches the note-commitment subtree roots for one shielded pool, decoding
/// each root hash with `read`. Errors surface as the raw tonic status so the
/// caller can distinguish a pool the server predates (rejected with
/// `InvalidArgument`) from a genuine transport failure.
async fn fetch_subtree_roots<N, F>(
    client: &mut CompactTxStreamerClient<Channel>,
    protocol: service::ShieldedProtocol,
    read: F,
) -> Result<Vec<CommitmentTreeRoot<N>>, tonic::Status>
where
    F: Fn(&[u8]) -> std::io::Result<N> + Copy,
{
    let mut request = service::GetSubtreeRootsArg::default();
    request.set_shielded_protocol(protocol);
    client
        .get_subtree_roots(request)
        .await?
        .into_inner()
        .and_then(|root| async move {
            let root_hash = read(&root.root_hash[..])?;
            Ok(CommitmentTreeRoot::from_parts(
                BlockHeight::from_u32(root.completing_block_height as u32),
                root_hash,
            ))
        })
        .try_collect()
        .await
}

/// Downloads note commitment subtree roots from lightwalletd for every shielded
/// pool and hands them to the wallet database.
pub(crate) async fn update_subtree_roots<P: Parameters>(
    client: &mut CompactTxStreamerClient<Channel>,
    db_data: &mut WalletDb<rusqlite::Connection, P, SystemClock, OsRng>,
) -> Result<(), anyhow::Error> {
    let sapling_roots = fetch_subtree_roots(client, service::ShieldedProtocol::Sapling, |b| {
        sapling::Node::read(b)
    })
    .await?;
    info!("Sapling tree has {} subtrees", sapling_roots.len());
    db_data.put_sapling_subtree_roots(0, &sapling_roots)?;

    let orchard_roots = fetch_subtree_roots(client, service::ShieldedProtocol::Orchard, |b| {
        MerkleHashOrchard::read(b)
    })
    .await?;
    info!("Orchard tree has {} subtrees", orchard_roots.len());
    db_data.put_orchard_subtree_roots(0, &orchard_roots)?;

    // Ironwood note commitments are Orchard-shaped, so its subtree roots use the
    // same hash type. A server that predates Ironwood activation simply streams
    // none; a server whose ShieldedProtocol enum predates Ironwood rejects the
    // value with InvalidArgument (e.g. zaino 0.4.3 on regtest), which means the
    // same thing.
    let ironwood_roots =
        match fetch_subtree_roots(client, service::ShieldedProtocol::Ironwood, |b| {
            MerkleHashOrchard::read(b)
        })
        .await
        {
            Ok(roots) => roots,
            Err(status) if status.code() == Code::InvalidArgument => {
                info!("Server does not recognize the Ironwood pool; assuming no subtrees");
                Vec::new()
            }
            Err(status) => return Err(status.into()),
        };
    info!("Ironwood tree has {} subtrees", ironwood_roots.len());
    db_data.put_ironwood_subtree_roots(0, &ironwood_roots)?;

    Ok(())
}

/// Downloads the chain tip from lightwalletd and notifies the wallet database of
/// it, returning the tip height and hash.
pub(crate) async fn update_chain_tip<P: Parameters>(
    client: &mut CompactTxStreamerClient<Channel>,
    db_data: &mut WalletDb<rusqlite::Connection, P, SystemClock, OsRng>,
) -> Result<(BlockHeight, BlockHash), anyhow::Error> {
    let latest = client
        .get_latest_block(service::ChainSpec::default())
        .await?
        .into_inner();
    let tip_height: BlockHeight = latest
        .height
        .try_into()
        .map_err(|_| anyhow!("chain tip height {} is out of range", latest.height))?;
    let tip_hash = BlockHash(
        latest
            .hash
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("chain tip block hash was not 32 bytes"))?,
    );

    info!("Latest block height is {}", tip_height);
    db_data.update_chain_tip(tip_height)?;

    Ok((tip_height, tip_hash))
}

/// Downloads the compact blocks in `scan_range` into the `FsBlockDb` cache with
/// an ordinary `GetBlockRange`, returning their metadata.
///
/// `after_each` is invoked with each downloaded block's metadata as it arrives
/// and returns `true` to stop downloading early (used by `wallet sync` for
/// progress reporting and shutdown; `advice receive` passes a no-op).
pub(crate) async fn download_blocks<F>(
    client: &mut CompactTxStreamerClient<Channel>,
    fsblockdb_root: &Path,
    db_cache: &FsBlockDb,
    scan_range: &ScanRange,
    mut after_each: F,
) -> Result<Vec<BlockMeta>, anyhow::Error>
where
    F: FnMut(&BlockMeta) -> bool,
{
    info!("Fetching {}", scan_range);
    let mut start = service::BlockId::default();
    start.height = scan_range.block_range().start.into();
    let mut end = service::BlockId::default();
    end.height = (scan_range.block_range().end - 1).into();
    let range = service::BlockRange {
        start: Some(start),
        end: Some(end),
        pool_types: Default::default(),
    };
    let block_meta_stream = client
        .get_block_range(range)
        .await
        .map_err(anyhow::Error::from)?
        .into_inner()
        .and_then(|block| async move {
            let (sapling_outputs_count, orchard_actions_count) = block
                .vtx
                .iter()
                .map(|tx| (tx.outputs.len() as u32, tx.actions.len() as u32))
                .fold((0, 0), |(acc_sapling, acc_orchard), (sapling, orchard)| {
                    (acc_sapling + sapling, acc_orchard + orchard)
                });

            let meta = BlockMeta {
                height: block.height(),
                block_hash: block.hash(),
                block_time: block.time,
                sapling_outputs_count,
                orchard_actions_count,
            };

            let encoded = block.encode_to_vec();
            let mut block_file = File::create(get_block_path(fsblockdb_root, &meta)).await?;
            block_file.write_all(&encoded).await?;

            Ok(meta)
        });
    tokio::pin!(block_meta_stream);

    let mut block_meta = vec![];
    while let Some(block) = block_meta_stream.try_next().await? {
        let stop = after_each(&block);
        block_meta.push(block);
        if stop {
            break;
        }
    }

    db_cache
        .write_block_metadata(&block_meta)
        .map_err(error::Error::from)?;

    Ok(block_meta)
}

/// Downloads the note commitment tree state as of the end of `block_height`,
/// used as the starting state for scanning the range that begins at
/// `block_height + 1`.
pub(crate) async fn download_chain_state(
    client: &mut CompactTxStreamerClient<Channel>,
    block_height: BlockHeight,
) -> Result<ChainState, anyhow::Error> {
    let tree_state = client
        .get_tree_state(BlockId {
            height: block_height.into(),
            hash: vec![],
        })
        .await?;

    Ok(tree_state.into_inner().to_chain_state()?)
}

/// Spawns a task that deletes the given cached compact-block files, tolerating
/// files that are already gone.
pub(crate) fn delete_cached_blocks(
    fsblockdb_root: &Path,
    block_meta: Vec<BlockMeta>,
) -> JoinHandle<()> {
    let fsblockdb_root = fsblockdb_root.to_owned();
    tokio::spawn(async move {
        for meta in block_meta {
            if let Err(e) = tokio::fs::remove_file(get_block_path(&fsblockdb_root, &meta)).await {
                // A file already removed (e.g. by a reorg rewind that deleted the
                // orphaned suffix) is not an error worth reporting.
                if e.kind() != std::io::ErrorKind::NotFound {
                    error!("Failed to remove {:?}: {}", meta, e);
                }
            }
        }
    })
}

/// Recovers from a scan continuity error detected at `at_height` (the height
/// whose linkage contradicts our stored history — a reorg, or the birthday
/// boundary on a freshly restored wallet) by rewinding the wallet and block
/// cache to `requested` (typically `at_height - REORG_REWIND_MARGIN`).
///
/// `truncate_to_height` can only rewind to a height carrying a
/// note-commitment-tree checkpoint, so if `requested` has none we retry at
/// `at_height - 2` (strictly below the stale block at `at_height - 1`, which
/// also guarantees forward progress). If even that has no checkpoint the reorg
/// is deeper than our rewindable history and we return an actionable "reset the
/// wallet" error rather than silently wedging. Shared by `wallet sync` and
/// `advice receive`'s completeness scan.
pub(crate) fn rewind<P: Parameters>(
    db_data: &mut WalletDb<rusqlite::Connection, P, SystemClock, OsRng>,
    db_cache: &mut FsBlockDb,
    fsblockdb_root: &Path,
    at_height: BlockHeight,
    requested: BlockHeight,
    chain_tip: BlockHeight,
) -> Result<(), anyhow::Error> {
    let rewind_height = match db_data.truncate_to_height(requested) {
        Ok(h) => h,
        Err(SqliteClientError::RequestedRewindInvalid { .. }) => {
            let bound = at_height.saturating_sub(2);
            match db_data.truncate_to_height(bound) {
                Ok(h) => {
                    info!("Requested rewind to {requested} had no checkpoint; rewound to {h}");
                    h
                }
                Err(SqliteClientError::RequestedRewindInvalid { .. }) => {
                    return Err(anyhow!(
                        "unrecoverable reorg at {at_height}: no note-commitment-tree \
                         checkpoint with a scanned block exists below the conflict \
                         (requested rewind to {requested}); reset the wallet to resync \
                         from its birthday"
                    ));
                }
                Err(e) => return Err(e.into()),
            }
        }
        Err(e) => return Err(e.into()),
    };

    // Delete cached compact-block files above the rewind height, then truncate
    // the block metadata to match.
    delete_block_files_above(fsblockdb_root, rewind_height);
    db_cache
        .truncate_to_height(rewind_height)
        .map_err(|e| anyhow!("{:?}", e))?;

    // Re-apply the chain tip. `truncate_to_height` trims the scan queue down to
    // the rewound height, so without this the wallet would believe it has
    // nothing left to scan and would stop at the rewind height instead of
    // re-scanning the replacement chain up to the tip.
    db_data.update_chain_tip(chain_tip)?;

    Ok(())
}

/// Deletes cached compact-block files whose height is above `height`, tolerating
/// files that are already gone.
///
/// We enumerate the blocks directory directly rather than using
/// `FsBlockDb::with_blocks`, because that opens each block file and would fail on
/// any file already deleted after scanning — the common case when rewinding
/// while fully synced, where the metadata outlives the file. Files are named
/// `<height>-<hash>-compactblock`, so the height is the leading component.
fn delete_block_files_above(fsblockdb_root: &Path, height: BlockHeight) {
    let Ok(entries) = std::fs::read_dir(get_blocks_dir(fsblockdb_root)) else {
        return;
    };
    for entry in entries.flatten() {
        let file_height = entry
            .file_name()
            .to_str()
            .and_then(|n| n.split('-').next())
            .and_then(|h| h.parse::<u32>().ok());
        if file_height.is_some_and(|h| h > u32::from(height)) {
            // Best-effort: a missing file has already served our purpose.
            if let Err(e) = std::fs::remove_file(entry.path()) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    error!("Failed to delete cached block {:?}: {}", entry.path(), e);
                }
            }
        }
    }
}
