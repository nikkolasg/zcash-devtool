use std::time::{Duration, Instant};

use anyhow::anyhow;
use clap::Args;
use tracing::{info, warn};
use uuid::Uuid;
use zcash_client_backend::{
    TransferType, data_api::WalletRead, decrypt_transaction, proto::service,
};
use zcash_client_sqlite::{AccountUuid, WalletDb};
use zcash_protocol::consensus::BlockHeight;

use crate::{
    commands::advice::{
        AdviceEnvelope, identity, parse_txid, pool_byte, process_ack_message, store,
        wait_message_of_type,
    },
    config::get_wallet_network,
    data::get_db_paths,
    helpers::tx_fetch::fetch_transaction,
    remote::ConnectionArgs,
    simplex::SimplexClient,
};

// Options accepted for the `advice send` command
#[derive(Debug, Args)]
pub(crate) struct Command {
    /// The UUID of the account that sent the transaction
    account_id: Option<Uuid>,

    /// WebSocket URL of the local simplex-chat CLI
    #[arg(long)]
    ws: String,

    /// Display name of the SimpleX contact to send the advice to
    #[arg(long)]
    to: String,

    /// The txid (display-order hex) of the mined transaction to advise about
    #[arg(long)]
    txid: String,

    /// age identity file for the wallet mnemonic; when given, the advice
    /// envelope is signed with the sender's identity subkey
    #[arg(long)]
    identity: Option<String>,

    /// Identity subkey index to sign the envelope with
    #[arg(long, default_value_t = 0)]
    index: u32,

    /// How long to wait for the recipient's acknowledgment, in seconds
    /// (0 = don't wait)
    #[arg(long, default_value_t = 20)]
    ack_timeout: u64,

    #[command(flatten)]
    connection: ConnectionArgs,
}

impl Command {
    pub(crate) async fn run(mut self, wallet_dir: Option<String>) -> Result<(), anyhow::Error> {
        // Normalize once at the boundary: outbox entries and ack matching
        // compare txids as strings, so mixed-case input must not create
        // duplicate or unmatchable entries.
        self.txid.make_ascii_lowercase();
        // Sent advice is persisted for later re-delivery, so the axion state
        // location must be known before any work is done.
        let axion_dir = store::require_wallet_dir(wallet_dir.as_ref())?;
        let params = get_wallet_network(wallet_dir.as_ref())?;
        let (_, db_data) = get_db_paths(wallet_dir.as_ref());
        let db_data = WalletDb::for_path(db_data, params, (), ())?;

        let txid = parse_txid(&self.txid)?;

        let mut client = self.connection.connect(params, wallet_dir.as_ref()).await?;
        let latest = client
            .get_latest_block(service::ChainSpec::default())
            .await?
            .into_inner();
        let chain_tip = BlockHeight::from_u32(
            u32::try_from(latest.height).map_err(|_| anyhow!("chain tip height out of range"))?,
        );
        info!("Chain tip is at height {}", chain_tip);

        // The indexer follows the validator asynchronously and reports a
        // mempool transaction's "height" as the current tip until it catches
        // up, so a height is only trusted once the indexer itself shows at
        // least one block on top of it. Advising a wrong height would make
        // the recipient reject the advice.
        let (tx, mined_height) = {
            let mut attempt = 0;
            loop {
                let fetched = fetch_transaction(&mut client, &params, chain_tip, txid)
                    .await?
                    .ok_or_else(|| anyhow!("transaction {} not found on the server", self.txid))?;
                let server_tip = client
                    .get_latest_block(service::ChainSpec::default())
                    .await?
                    .into_inner()
                    .height;
                if let (tx, Some(height)) = fetched {
                    if u64::from(u32::from(height)) < server_tip {
                        break (tx, height);
                    }
                }
                attempt += 1;
                if attempt >= 30 {
                    return Err(anyhow!(
                        "transaction {} is not confirmed from the server's view; \
                         mine at least one block on top of it, then send advice",
                        self.txid
                    ));
                }
                info!("Waiting for the server to confirm the transaction's mined height...");
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        };
        info!(
            "Transaction {} is mined at height {}",
            self.txid, mined_height
        );

        let mut ufvks = db_data.get_unified_full_viewing_keys()?;
        if let Some(uuid) = self.account_id {
            let account_id = AccountUuid::from_uuid(uuid);
            ufvks.retain(|id, _| *id == account_id);
            if ufvks.is_empty() {
                return Err(anyhow!("no viewing key found for account {uuid}"));
            }
        }

        // One trial decryption with the sender's own keys, to locate the output
        // that pays the recipient (recoverable via the outgoing viewing key).
        let decrypted =
            decrypt_transaction(&params, Some(mined_height), Some(chain_tip), &tx, &ufvks);
        let outgoing_orchard = decrypted
            .orchard_outputs()
            .iter()
            .find(|o| o.transfer_type() == TransferType::Outgoing);
        let outgoing_sapling = decrypted
            .sapling_outputs()
            .iter()
            .find(|o| o.transfer_type() == TransferType::Outgoing);
        // Post-NU6.3, payments to orchard receivers are built into the Ironwood
        // bundle, so it must be searched too or every normal payment fails here.
        let outgoing_ironwood = decrypted
            .ironwood_outputs()
            .iter()
            .find(|o| o.transfer_type() == TransferType::Outgoing);
        let (pool, output_index) = if let Some(o) = outgoing_orchard {
            ("orchard", o.index())
        } else if let Some(o) = outgoing_ironwood {
            ("ironwood", o.index())
        } else if let Some(o) = outgoing_sapling {
            ("sapling", o.index())
        } else {
            return Err(anyhow!(
                "transaction {} has no outgoing shielded output decryptable by this wallet; \
                 either it pays nobody external or this is the wrong wallet",
                self.txid
            ));
        };
        info!(
            "Found outgoing output at pool={} index={}",
            pool, output_index
        );

        let output_index =
            u32::try_from(output_index).map_err(|_| anyhow!("output index out of range"))?;
        let mut envelope = AdviceEnvelope {
            v: 1,
            kind: "advice".to_string(),
            txid: self.txid.clone(),
            height: u32::from(mined_height),
            pool: pool.to_string(),
            output_index,
            sig: None,
        };
        // Sign the envelope with the sender's identity subkey. The signature
        // is domain-separated but deliberately not channel-bound: it must
        // stay verifiable when the envelope is re-delivered over a different
        // channel after the recipient recovers from seed.
        if let Some(identity_file) = &self.identity {
            // The subkey index recorded at pairing time (when our token went
            // to this peer) wins over the command-line one, mirroring how
            // `advice receive` picks its ack-signing key; otherwise a pairing
            // done with a non-default index would sign with the wrong subkey
            // and the peer would reject every envelope.
            let index = store::load_peers(&axion_dir)?
                .get(&self.to)
                .and_then(|p| p.my_index)
                .unwrap_or(self.index);
            let sk = identity::wallet_signing_key(wallet_dir.as_ref(), identity_file, index)?;
            let sig = sk.sign(&identity::advice_signing_input(
                txid.as_ref(),
                envelope.height,
                pool_byte(&envelope.pool)?,
                envelope.output_index,
            ));
            envelope.sig = Some(hex::encode(sig.to_bytes()));
        } else {
            warn!("no --identity given; sending an unauthenticated advice envelope");
        }
        let envelope_json = serde_json::to_string(&envelope)?;

        let mut simplex = SimplexClient::connect(&self.ws).await?;
        simplex.send_text(&self.to, &envelope_json).await?;

        // The outbox keeps the envelope with its signature so recovery
        // re-delivery replays exactly what was originally sent.
        store::append_outbox(&axion_dir, &self.to, serde_json::to_value(&envelope)?)?;
        info!("Advice appended to the outbox for {}", self.to);

        println!("{envelope_json}");
        println!("Advice sent to {} over SimpleX.", self.to);

        if self.ack_timeout > 0 {
            self.wait_for_ack(&mut simplex, &axion_dir, &params).await?;
        }

        Ok(())
    }

    /// Waits for the recipient's acknowledgment of this txid and applies the
    /// address ratchet (spec 1.3.3). Only a signature-valid ack may change
    /// state; a bad or missing signature (while a peer key is stored) is
    /// warned about and skipped, leaving the outbox entry and working address
    /// untouched. On timeout the advice stays pending; a later ack is picked up
    /// by `advice flush` or a future `advice send` for the same txid.
    async fn wait_for_ack(
        &self,
        simplex: &mut SimplexClient,
        axion_dir: &std::path::Path,
        params: &crate::data::Network,
    ) -> Result<(), anyhow::Error> {
        let peers = store::load_peers(axion_dir)?;
        let stored_pubkey = peers.get(&self.to).map(|peer| peer.pubkey.clone());

        info!(
            "Waiting up to {}s for an ack from {}",
            self.ack_timeout, self.to
        );
        let wanted_txids = [self.txid.clone()];
        let deadline = Instant::now() + Duration::from_secs(self.ack_timeout);
        loop {
            let Some((_, text)) =
                wait_message_of_type(simplex, &self.to, &["ack"], deadline).await?
            else {
                println!(
                    "no ack received within {}s; advice stays pending in the outbox (run \
                     `advice flush` to re-send it and pick up a late ack)",
                    self.ack_timeout
                );
                return Ok(());
            };
            if process_ack_message(
                axion_dir,
                params,
                &self.to,
                stored_pubkey.as_deref(),
                &wanted_txids,
                &text,
            )?
            .is_some()
            {
                return Ok(());
            }
        }
    }
}
