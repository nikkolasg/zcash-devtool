use std::collections::BTreeSet;

use anyhow::anyhow;
use clap::Args;
use futures_util::StreamExt;
use rand::rngs::OsRng;
use tracing::info;
use zcash_client_backend::{
    data_api::{
        TransactionDataRequest, TransactionStatus, WalletRead, WalletWrite,
        wallet::decrypt_and_store_transaction,
    },
    proto::service::{self, BlockRange},
};
use zcash_client_sqlite::{WalletDb, util::SystemClock};
use zcash_keys::encoding::AddressCodec;

use crate::{
    config::get_wallet_network,
    data::get_db_paths,
    helpers::tx_fetch::{fetch_transaction, parse_raw_transaction},
    remote::ConnectionArgs,
};

// Options accepted for the `enhance` command
#[derive(Debug, Args)]
pub(crate) struct Command {
    #[command(flatten)]
    connection: ConnectionArgs,
}

impl Command {
    pub(crate) async fn run(self, wallet_dir: Option<String>) -> Result<(), anyhow::Error> {
        let params = get_wallet_network(wallet_dir.as_ref())?;
        let (_, db_data) = get_db_paths(wallet_dir.as_ref());

        let mut db_data = WalletDb::for_path(db_data, params, SystemClock, OsRng)?;
        let chain_tip = db_data.chain_height()?.ok_or_else(|| {
            anyhow!("Chain height must be available to perform transaction enhancement.")
        })?;

        // TODO:
        // - Create a shared Tor client.
        // - Create an isolated `lightwalletd` connection for each transaction.
        // - Spread transactions across all available servers.
        // - Fetch transactions in parallel, with timing noise.
        let mut client = self.connection.connect(params, wallet_dir.as_ref()).await?;

        let mut satisfied_requests = BTreeSet::new();
        loop {
            let mut new_request_encountered = false;
            for data_request in db_data.transaction_data_requests()? {
                if satisfied_requests.contains(&data_request) {
                    continue;
                } else {
                    new_request_encountered = true;
                }

                info!("Fetching data for request {:?}", data_request);
                match &data_request {
                    TransactionDataRequest::GetStatus(txid) => {
                        let status = fetch_transaction(&mut client, &params, chain_tip, *txid)
                            .await?
                            .map_or(TransactionStatus::TxidNotRecognized, |(_, mined_height)| {
                                mined_height.map_or(
                                    TransactionStatus::NotInMainChain,
                                    TransactionStatus::Mined,
                                )
                            });
                        info!("Got status {:?}", status);
                        db_data.set_transaction_status(*txid, status)?;
                    }
                    TransactionDataRequest::Enhancement(txid) => {
                        match fetch_transaction(&mut client, &params, chain_tip, *txid).await? {
                            None => {
                                info!("Txid not recognized {:?}", txid);
                                db_data.set_transaction_status(
                                    *txid,
                                    TransactionStatus::TxidNotRecognized,
                                )?;
                            }
                            Some((tx, mined_height)) => {
                                info!(
                                    "Enhancing tx {:?} with mined height {:?}",
                                    txid, mined_height
                                );
                                decrypt_and_store_transaction(
                                    &params,
                                    &mut db_data,
                                    &tx,
                                    mined_height,
                                )?;
                            }
                        }
                    }
                    TransactionDataRequest::TransactionsInvolvingAddress(tia) => {
                        let address = tia.address().encode(&params);
                        let request = service::TransparentAddressBlockFilter {
                            address: address.clone(),
                            range: Some(BlockRange {
                                start: Some(service::BlockId {
                                    height: u64::from(tia.block_range_start()),
                                    ..Default::default()
                                }),
                                end: tia.block_range_end().map(|h| service::BlockId {
                                    height: u64::from(h - 1), // `BlockRange` end is inclusive.
                                    ..Default::default()
                                }),
                                pool_types: Default::default(),
                            }),
                        };

                        let mut stream = client.get_taddress_txids(request).await?.into_inner();
                        while let Some(raw_tx) = stream.next().await {
                            let (tx, mined_height) =
                                parse_raw_transaction(&params, chain_tip, raw_tx?)?;
                            info!(
                                "Found tx {:?} for address {} with mined height {:?}",
                                tx.txid(),
                                address,
                                mined_height
                            );
                            decrypt_and_store_transaction(&params, &mut db_data, &tx, mined_height)?
                        }
                    }
                }

                satisfied_requests.insert(data_request);
            }

            if !new_request_encountered {
                break;
            }
        }

        Ok(())
    }
}
