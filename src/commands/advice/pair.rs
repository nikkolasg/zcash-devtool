use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::anyhow;
use clap::{Args, ValueEnum};
use ed25519_zebra::SigningKey;
use rand::rngs::OsRng;
use tracing::info;
use zcash_client_sqlite::{WalletDb, util::SystemClock};

use crate::{
    commands::advice::{
        TokenMessage, decode_hex_array, identity, mint_next_address,
        store::{self, PeerIdentity},
        validate_token, wait_message_of_type,
    },
    config::get_wallet_network,
    data::get_db_paths,
    simplex::SimplexClient,
};

const PAIRING_TIMEOUT: Duration = Duration::from_secs(120);
/// How long either side waits for an optional identity token after the
/// connection completes. Short: peers that send one do so immediately.
const TOKEN_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Mode {
    /// Create an invitation and wait for the peer to join.
    Invite,
    /// Join a peer's invitation link.
    Join,
}

// Options accepted for the `advice pair` command
#[derive(Debug, Args)]
pub(crate) struct Command {
    /// WebSocket URL of the local simplex-chat CLI (e.g. ws://127.0.0.1:5226)
    #[arg(long)]
    ws: String,

    /// Whether to create an invitation or join one
    #[arg(long, value_enum)]
    mode: Mode,

    /// The invitation link to join (required with `--mode join`)
    #[arg(long)]
    link: Option<String>,

    /// File to write the invitation link to (with `--mode invite`)
    #[arg(long)]
    link_out: Option<PathBuf>,

    /// age identity file for the wallet mnemonic; send a signed identity
    /// token to the peer after pairing (with `--mode invite`, the token also
    /// carries a freshly minted diversified address for the peer to pay)
    #[arg(long)]
    identity: Option<String>,

    /// Identity subkey index to use for the token. Defaults to a freshly
    /// allocated per-contact index so every contact gets a distinct
    /// verification key (spec 1.3.5); pin it only to reproduce a known pairing.
    #[arg(long)]
    index: Option<u32>,
}

/// Signs and sends this wallet's identity token to `name` over the pairing
/// channel `link`. `address` is the freshly minted diversified address the
/// peer should pay (invite side); identity-only reply tokens pass `None`.
async fn send_identity_token(
    simplex: &mut SimplexClient,
    name: &str,
    sk: &SigningKey,
    index: u32,
    address: Option<&str>,
    link: &str,
) -> anyhow::Result<()> {
    let pubkey = identity::public_key_bytes(sk);
    let sig = sk.sign(&identity::token_signing_input(
        index,
        &pubkey,
        &identity::link_binding(link),
        address.unwrap_or("").as_bytes(),
    ));
    let token = TokenMessage {
        v: 1,
        kind: "token".to_string(),
        j: index,
        pubkey: hex::encode(pubkey),
        address: address.map(str::to_owned),
        sig: hex::encode(sig.to_bytes()),
    };
    simplex
        .send_text(name, &serde_json::to_string(&token)?)
        .await?;
    match address {
        Some(address) => println!(
            "Identity token delivered to {name} (j={index}, pubkey={}, address {address})",
            token.pubkey
        ),
        None => println!(
            "Identity token delivered to {name} (j={index}, pubkey={})",
            token.pubkey
        ),
    }
    Ok(())
}

/// Verifies a received token's channel-bound self-signature and stores the
/// peer's identity. `my_index` records which of our own subkey indexes this
/// relationship uses (None when we sent no token ourselves).
fn verify_and_store_token(
    wallet_dir: Option<&String>,
    name: &str,
    text: &str,
    link: &str,
    my_index: Option<u32>,
) -> Result<(), anyhow::Error> {
    let token =
        validate_token(text).map_err(|e| anyhow!("invalid identity token from {name}: {e}"))?;
    let pubkey = decode_hex_array::<32>(&token.pubkey)?;
    let sig = decode_hex_array::<64>(&token.sig)?;
    // The signature covers the address bytes too (empty when absent), so a
    // relay cannot swap the pay-to address inside an otherwise valid token.
    let address_bytes = token.address.as_deref().unwrap_or("").as_bytes();
    identity::verify_signature(
        &pubkey,
        &identity::token_signing_input(
            token.j,
            &pubkey,
            &identity::link_binding(link),
            address_bytes,
        ),
        &sig,
    )
    .map_err(|e| {
        anyhow!(
            "identity token from {name} is invalid (bad signature or a token replayed from \
             another channel): {e}"
        )
    })?;
    let dir = store::require_wallet_dir(wallet_dir)?;
    // A signed-but-undecodable address must not be stored as the pay-to
    // address: it would wedge every later payment to this contact.
    let working_address = match &token.address {
        Some(address) => {
            let params = get_wallet_network(wallet_dir)?;
            if crate::commands::advice::is_valid_address(&params, address) {
                Some(address.clone())
            } else {
                println!(
                    "warning: token address from {name} does not decode for this network; \
                     ignoring it"
                );
                None
            }
        }
        None => None,
    };
    store::save_peer(
        &dir,
        name,
        PeerIdentity {
            j: token.j,
            pubkey: token.pubkey.clone(),
            working_address,
            my_index,
            next_ack_counter: None,
            last_ack_counter: None,
        },
    )?;
    match &token.address {
        Some(address) => println!(
            "Identity token stored for {name} (j={}, pubkey={}, working address {address})",
            token.j, token.pubkey
        ),
        None => println!(
            "Identity token stored for {name} (j={}, pubkey={})",
            token.j, token.pubkey
        ),
    }
    Ok(())
}

impl Command {
    pub(crate) async fn run(self, wallet_dir: Option<String>) -> Result<(), anyhow::Error> {
        // Allocate a fresh per-contact identity index unless one is pinned on
        // the command line, so every contact gets a distinct verification key
        // (spec 1.3.5). Done before connecting so a missing wallet dir fails
        // fast. `None` when no identity token will be sent at all.
        let my_index = match &self.identity {
            Some(_) => Some(match self.index {
                Some(index) => index,
                None => store::allocate_identity_index(&store::require_wallet_dir(
                    wallet_dir.as_ref(),
                )?)?,
            }),
            None => None,
        };

        let mut simplex = SimplexClient::connect(&self.ws).await?;

        match self.mode {
            Mode::Invite => {
                let link = simplex.create_invitation().await?;
                println!("{link}");
                if let Some(path) = &self.link_out {
                    std::fs::write(path, &link)?;
                    info!("Invitation link written to {}", path.display());
                }
                info!("Waiting for the peer to join the invitation...");
                let name = simplex.wait_contact_connected(PAIRING_TIMEOUT).await?;
                println!("Connected to contact: {name}");

                if let Some(identity_file) = &self.identity {
                    let index = my_index.expect("index resolved whenever an identity is given");
                    let sk =
                        identity::wallet_signing_key(wallet_dir.as_ref(), identity_file, index)?;
                    // Mint a fresh diversified address dedicated to this
                    // contact and carry it in the token; the sender pays it
                    // until an accepted-ack ratchets it forward.
                    let params = get_wallet_network(wallet_dir.as_ref())?;
                    let (_, db_path) = get_db_paths(wallet_dir.as_ref());
                    let mut db_data = WalletDb::for_path(db_path, params, SystemClock, OsRng)?;
                    let address = mint_next_address(&params, &mut db_data)?;
                    send_identity_token(&mut simplex, &name, &sk, index, Some(&address), &link)
                        .await?;
                }

                // The joining side may send its own identity token back; a
                // peer that does not is still a valid pairing partner.
                info!(
                    "Waiting up to {:?} for an identity token from {name}",
                    TOKEN_TIMEOUT
                );
                let deadline = Instant::now() + TOKEN_TIMEOUT;
                match wait_message_of_type(&mut simplex, &name, &["token"], deadline).await? {
                    Some((_, text)) => {
                        verify_and_store_token(wallet_dir.as_ref(), &name, &text, &link, my_index)?
                    }
                    None => println!(
                        "No identity token received from {name}; its advice envelopes and acks \
                         will be unverifiable."
                    ),
                }
            }
            Mode::Join => {
                let link = self
                    .link
                    .ok_or_else(|| anyhow!("--link is required with --mode join"))?;
                simplex.join(&link).await?;
                info!("Joined invitation; waiting for the connection to complete...");
                let name = simplex.wait_contact_connected(PAIRING_TIMEOUT).await?;
                println!("Connected to contact: {name}");

                // Send our own identity token (identity-only, no address) so
                // the peer can verify our advice envelope signatures later.
                // Same channel binding as the peer's token. Sent before
                // waiting for the peer's token: both sides wait ~15s for the
                // other's token, so replying only after our wait resolves
                // would arrive past a token-less inviter's deadline.
                if let Some(identity_file) = &self.identity {
                    let index = my_index.expect("index resolved whenever an identity is given");
                    let sk =
                        identity::wallet_signing_key(wallet_dir.as_ref(), identity_file, index)?;
                    send_identity_token(&mut simplex, &name, &sk, index, None, &link).await?;
                } else {
                    println!(
                        "No --identity given; not sending an identity token back to {name} \
                         (our advice envelopes will be unauthenticated)."
                    );
                }

                // The peer may send an identity token right after pairing; a
                // peer without one is still a valid pairing partner.
                info!(
                    "Waiting up to {:?} for an identity token from {name}",
                    TOKEN_TIMEOUT
                );
                let deadline = Instant::now() + TOKEN_TIMEOUT;
                match wait_message_of_type(&mut simplex, &name, &["token"], deadline).await? {
                    Some((_, text)) => {
                        verify_and_store_token(wallet_dir.as_ref(), &name, &text, &link, my_index)?
                    }
                    None => println!(
                        "No identity token received from {name}; recovery re-delivery \
                         will not be available for this peer."
                    ),
                }
            }
        }

        Ok(())
    }
}
