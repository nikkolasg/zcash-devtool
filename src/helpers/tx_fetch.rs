//! Shared helpers for fetching and parsing individual transactions from a
//! lightwalletd-compatible server.

use tonic::{Code, transport::Channel};
use zcash_client_backend::proto::service::{
    self, RawTransaction, compact_tx_streamer_client::CompactTxStreamerClient,
};
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_protocol::consensus::{BlockHeight, BranchId, Parameters};

pub(crate) fn parse_raw_transaction<P: Parameters>(
    params: &P,
    chain_tip: BlockHeight,
    tx: RawTransaction,
) -> Result<(Transaction, Option<BlockHeight>), anyhow::Error> {
    let mined_height = (tx.height > 0 && tx.height <= u64::from(u32::MAX))
        .then(|| BlockHeight::from_u32(u32::try_from(tx.height).unwrap()));

    let tx = Transaction::read(
        &tx.data[..],
        // We assume unmined transactions are created with the current consensus branch ID.
        BranchId::for_height(params, mined_height.unwrap_or(chain_tip)),
    )?;

    Ok((tx, mined_height))
}

pub(crate) async fn fetch_transaction<P: Parameters>(
    client: &mut CompactTxStreamerClient<Channel>,
    params: &P,
    chain_tip: BlockHeight,
    txid: TxId,
) -> Result<Option<(Transaction, Option<BlockHeight>)>, anyhow::Error> {
    let request = service::TxFilter {
        hash: txid.as_ref().to_vec(),
        ..Default::default()
    };

    let raw_tx = match client.get_transaction(request).await {
        Ok(response) => Ok(Some(response.into_inner())),
        Err(status) => {
            if status.code() == Code::NotFound {
                Ok(None)
            } else {
                Err(status)
            }
        }
    }?;

    raw_tx
        .map(|raw_tx| parse_raw_transaction(params, chain_tip, raw_tx))
        .transpose()
}
