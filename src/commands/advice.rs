use std::path::Path;
use std::time::Instant;

use anyhow::anyhow;
use clap::Subcommand;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};
use zcash_client_backend::data_api::{Account, WalletWrite};
use zcash_client_sqlite::AccountUuid;
use zcash_keys::keys::UnifiedAddressRequest;
use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::Parameters;

use crate::simplex::SimplexClient;

pub(crate) mod identity;
pub(crate) mod pair;
pub(crate) mod store;

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Pair with a peer over a SimpleX messaging channel
    Pair(pair::Command),
}

/// The out-of-band advice message exchanged over SimpleX. `sig` is an
/// optional Ed25519 signature by the sender's identity subkey over
/// [`identity::advice_signing_input`]; envelopes from pre-signature senders
/// have none.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct AdviceEnvelope {
    pub(crate) v: u32,
    #[serde(rename = "type")]
    pub(crate) kind: String,
    pub(crate) txid: String,
    pub(crate) height: u32,
    pub(crate) pool: String,
    pub(crate) output_index: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) sig: Option<String>,
}

/// Identity token exchanged at pairing time; the self-signature binds the
/// subkey index to the public key (and the channel, and the address when one
/// is carried). The invite side's token also carries a freshly minted
/// diversified `address` for the sender to pay; identity-only reply tokens
/// omit it.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct TokenMessage {
    pub(crate) v: u32,
    #[serde(rename = "type")]
    pub(crate) kind: String,
    pub(crate) j: u32,
    pub(crate) pubkey: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) address: Option<String>,
    pub(crate) sig: String,
}

/// Acknowledgment of one advice, sent by the recipient after (or instead of)
/// verification. An accepted-ack piggybacks the next fresh diversified
/// address, ratcheting the address the sender pays (spec 1.3.3); an
/// invalid-ack carries an empty `next_address`. The signature is NOT
/// channel-bound (like advice, it is a property of the payment relationship,
/// not the channel; the channel's own ratchet still authenticates transport).
/// `counter` is the recipient's per-relationship monotonic sequence; the sender
/// only acts on an ack whose counter is strictly greater than the last it
/// accepted, which defeats replay of a captured ack.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct AckMessage {
    pub(crate) v: u32,
    #[serde(rename = "type")]
    pub(crate) kind: String,
    pub(crate) txid: String,
    pub(crate) status: String,
    pub(crate) next_address: String,
    pub(crate) counter: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) sig: Option<String>,
}

/// Challenge sent by the advice sender over a fresh channel to a wallet
/// claiming to be a recovered peer.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct RecoveryChallengeMessage {
    pub(crate) v: u32,
    #[serde(rename = "type")]
    pub(crate) kind: String,
    pub(crate) nonce: String,
}

/// The recovered wallet's answer: a signature over the challenge nonce with
/// the identity subkey the sender has held since first pairing.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct RecoveryProofMessage {
    pub(crate) v: u32,
    #[serde(rename = "type")]
    pub(crate) kind: String,
    pub(crate) j: u32,
    pub(crate) pubkey: String,
    pub(crate) sig: String,
}

/// Marks the end of a re-delivery batch.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct RedeliveryDoneMessage {
    pub(crate) v: u32,
    #[serde(rename = "type")]
    pub(crate) kind: String,
    pub(crate) count: u32,
}

/// A chunk of re-delivered advice envelopes packed into one message. Each
/// SimpleX message costs a full client/relay round-trip (~0.2s on the
/// reference stack), so re-delivery ships many envelopes per message instead
/// of one; entries are validated individually on receipt.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct AdviceBatchMessage {
    pub(crate) v: u32,
    #[serde(rename = "type")]
    pub(crate) kind: String,
    pub(crate) advices: Vec<serde_json::Value>,
}

pub(crate) fn check_v1(v: u32) -> Result<(), String> {
    if v != 1 {
        return Err(format!("unsupported version {v}"));
    }
    Ok(())
}

pub(crate) fn check_kind(kind: &str, expected: &str) -> Result<(), String> {
    if kind != expected {
        return Err(format!("unexpected message type {kind:?}"));
    }
    Ok(())
}

pub(crate) fn check_hex(field: &str, value: &str, bytes: usize) -> Result<(), String> {
    if value.len() != bytes * 2 || !value.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("{field} must be {} hex characters", bytes * 2));
    }
    Ok(())
}

pub(crate) fn validate_token(text: &str) -> Result<TokenMessage, String> {
    let msg: TokenMessage = serde_json::from_str(text).map_err(|e| format!("invalid JSON: {e}"))?;
    check_v1(msg.v)?;
    check_kind(&msg.kind, "token")?;
    check_hex("pubkey", &msg.pubkey, 32)?;
    check_hex("sig", &msg.sig, 64)?;
    if msg.address.as_deref() == Some("") {
        return Err("address must be omitted rather than empty".to_string());
    }
    Ok(msg)
}

pub(crate) fn validate_ack(text: &str) -> Result<AckMessage, String> {
    let msg: AckMessage = serde_json::from_str(text).map_err(|e| format!("invalid JSON: {e}"))?;
    check_v1(msg.v)?;
    check_kind(&msg.kind, "ack")?;
    check_hex("txid", &msg.txid, 32)?;
    if !matches!(msg.status.as_str(), "accepted" | "invalid") {
        return Err(format!("unknown ack status {:?}", msg.status));
    }
    if let Some(sig) = &msg.sig {
        check_hex("sig", sig, 64)?;
    }
    Ok(msg)
}

pub(crate) fn validate_recovery_challenge(text: &str) -> Result<RecoveryChallengeMessage, String> {
    let msg: RecoveryChallengeMessage =
        serde_json::from_str(text).map_err(|e| format!("invalid JSON: {e}"))?;
    check_v1(msg.v)?;
    check_kind(&msg.kind, "recovery_challenge")?;
    check_hex("nonce", &msg.nonce, 32)?;
    Ok(msg)
}

pub(crate) fn validate_recovery_proof(text: &str) -> Result<RecoveryProofMessage, String> {
    let msg: RecoveryProofMessage =
        serde_json::from_str(text).map_err(|e| format!("invalid JSON: {e}"))?;
    check_v1(msg.v)?;
    check_kind(&msg.kind, "recovery_proof")?;
    check_hex("pubkey", &msg.pubkey, 32)?;
    check_hex("sig", &msg.sig, 64)?;
    Ok(msg)
}

pub(crate) fn validate_redelivery_done(text: &str) -> Result<RedeliveryDoneMessage, String> {
    let msg: RedeliveryDoneMessage =
        serde_json::from_str(text).map_err(|e| format!("invalid JSON: {e}"))?;
    check_v1(msg.v)?;
    check_kind(&msg.kind, "redelivery_done")?;
    Ok(msg)
}

pub(crate) fn validate_advice_batch(text: &str) -> Result<AdviceBatchMessage, String> {
    let msg: AdviceBatchMessage =
        serde_json::from_str(text).map_err(|e| format!("invalid JSON: {e}"))?;
    check_v1(msg.v)?;
    check_kind(&msg.kind, "advice_batch")?;
    Ok(msg)
}

/// Decodes a hex string that must encode exactly `N` bytes.
pub(crate) fn decode_hex_array<const N: usize>(s: &str) -> anyhow::Result<[u8; N]> {
    let bytes = hex::decode(s).map_err(|e| anyhow!("invalid hex: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("expected {N} bytes of hex"))
}

/// The one-byte pool encoding used in advice signing inputs.
pub(crate) fn pool_byte(pool: &str) -> anyhow::Result<u8> {
    match pool {
        "sapling" => Ok(0),
        "orchard" => Ok(1),
        "ironwood" => Ok(2),
        other => Err(anyhow!("unknown pool {other:?}")),
    }
}

/// The one-byte status encoding used in ack signing inputs.
pub(crate) fn ack_status_byte(status: &str) -> anyhow::Result<u8> {
    match status {
        "invalid" => Ok(0),
        "accepted" => Ok(1),
        other => Err(anyhow!("unknown ack status {other:?}")),
    }
}

/// Builds the byte string an envelope's signature covers from the envelope's
/// own fields. Fails only on a malformed txid or pool, which validation
/// rejects earlier on the receive path.
pub(crate) fn envelope_signing_input(envelope: &AdviceEnvelope) -> anyhow::Result<Vec<u8>> {
    let txid = parse_txid(&envelope.txid)?;
    Ok(identity::advice_signing_input(
        txid.as_ref(),
        envelope.height,
        pool_byte(&envelope.pool)?,
        envelope.output_index,
    ))
}

/// Builds the byte string an ack's signature covers from the ack's own fields.
pub(crate) fn ack_message_signing_input(ack: &AckMessage) -> anyhow::Result<Vec<u8>> {
    let txid = parse_txid(&ack.txid)?;
    Ok(identity::ack_signing_input(
        txid.as_ref(),
        ack_status_byte(&ack.status)?,
        ack.counter,
        &ack.next_address,
    ))
}

/// How an envelope's authenticity was established. Anything other than
/// `Authenticated` is surfaced on stdout by callers so operators scripting on
/// stdout can distinguish the cases.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EnvelopeAuth {
    /// Signature verified against the identity key stored for the peer.
    Authenticated,
    /// Signed, but no identity key is stored to verify against.
    Unverifiable,
    /// No signature (pre-signature sender); chain verification still governs.
    Unauthenticated,
}

/// Checks an advice envelope's signature against the peer key stored at
/// pairing time, if any. Policy: signature + stored key must verify (hard
/// error on mismatch); a signature without a stored key, or no signature at
/// all, is accepted with a warning — chain verification still governs whether
/// the payment is real.
pub(crate) fn check_envelope_signature(
    envelope: &AdviceEnvelope,
    stored_pubkey: Option<&str>,
) -> anyhow::Result<EnvelopeAuth> {
    match (&envelope.sig, stored_pubkey) {
        (Some(sig), Some(pubkey)) => {
            let pubkey = decode_hex_array::<32>(pubkey)?;
            let sig = decode_hex_array::<64>(sig)?;
            identity::verify_signature(&pubkey, &envelope_signing_input(envelope)?, &sig)
                .map_err(|_| {
                    anyhow!(
                        "envelope signature does not verify against the identity key stored for \
                         this peer"
                    )
                })
                .map(|()| EnvelopeAuth::Authenticated)
        }
        (Some(_), None) => {
            warn!(
                "envelope is signed but no identity key is stored for this peer; signature is \
                 unverifiable (chain verification still governs)"
            );
            Ok(EnvelopeAuth::Unverifiable)
        }
        (None, _) => {
            warn!("unauthenticated envelope (no signature); chain verification still governs");
            Ok(EnvelopeAuth::Unauthenticated)
        }
    }
}

/// Returns true when `addr` decodes as a Zcash address for this network.
/// Ratcheted working addresses and token addresses are validated with this
/// before being stored, so a buggy or malicious peer cannot wedge the sender
/// with an unpayable string.
pub(crate) fn is_valid_address(params: &impl Parameters, addr: &str) -> bool {
    zcash_keys::address::Address::decode(params, addr).is_some()
}

/// Checks an ack's signature against the peer key stored at pairing time.
/// Unlike advice, an ack drives a state change on the sender (the address
/// ratchet), so when a peer key IS stored, both a bad signature and a missing
/// one make the ack unusable (`Err`): the caller must ignore it and leave the
/// ratchet untouched. Without a stored key the ack is accepted with a warning.
pub(crate) fn check_ack_signature(
    ack: &AckMessage,
    stored_pubkey: Option<&str>,
) -> anyhow::Result<()> {
    match (&ack.sig, stored_pubkey) {
        (Some(sig), Some(pubkey)) => {
            let pubkey = decode_hex_array::<32>(pubkey)?;
            let sig = decode_hex_array::<64>(sig)?;
            identity::verify_signature(&pubkey, &ack_message_signing_input(ack)?, &sig).map_err(
                |_| {
                    anyhow!(
                        "ack signature does not verify against the identity key stored for this \
                         peer"
                    )
                },
            )
        }
        (None, Some(_)) => Err(anyhow!(
            "unsigned ack from a peer whose identity key is stored; refusing to act on it"
        )),
        (_, None) => {
            warn!("no identity key stored for this peer; accepting unverifiable ack");
            Ok(())
        }
    }
}

/// Processes one ack received from `contact` while advice for `wanted_txids`
/// (lowercase display-order hex) is outstanding: validation, signature
/// policy, outbox status update, and the working-address ratchet (spec
/// 1.3.3). Shared by `advice send` and `advice flush`. Returns the txid the
/// ack resolved, or None when the message was ignored (malformed, unrelated
/// txid, or unusable signature — warned about, never fatal, so the caller's
/// wait keeps going).
pub(crate) fn process_ack_message(
    axion_dir: &Path,
    params: &impl Parameters,
    contact: &str,
    stored_pubkey: Option<&str>,
    wanted_txids: &[String],
    text: &str,
) -> anyhow::Result<Option<String>> {
    let ack = match validate_ack(text) {
        Ok(ack) => ack,
        Err(e) => {
            warn!("ignoring malformed ack from {contact}: {e}");
            return Ok(None);
        }
    };
    let txid = ack.txid.to_ascii_lowercase();
    if !wanted_txids.contains(&txid) {
        debug!("ignoring ack for an unexpected txid {}", ack.txid);
        return Ok(None);
    }
    if let Err(e) = check_ack_signature(&ack, stored_pubkey) {
        warn!("ignoring ack from {contact}: {e}");
        return Ok(None);
    }
    // Replay guard: a signature-valid ack only advances state if its counter is
    // strictly newer than the last accepted from this peer, so a captured ack
    // cannot be replayed to roll the working address backward.
    // The high-water mark advances only past signature verification, so a
    // forged counter cannot poison it. A no-op when no peer entry is stored
    // (the same unverifiable case check_ack_signature only warns about).
    if !store::accept_incoming_counter(axion_dir, contact, ack.counter)? {
        warn!(
            "ignoring stale ack from {contact}: counter {} not newer than the last accepted",
            ack.counter
        );
        return Ok(None);
    }
    match ack.status.as_str() {
        "accepted" => {
            if !store::set_outbox_status(axion_dir, contact, &txid, store::OutboxStatus::Acked)? {
                // The ack's txid signed-and-verified but matches no pending
                // outbox entry — surface it rather than reporting resolved.
                warn!("ack from {contact} references txid {txid} with no matching outbox entry");
                return Ok(None);
            }
            if ack.next_address.is_empty() {
                println!("ack received: accepted (no next address; ratchet unchanged)");
            } else if !is_valid_address(params, &ack.next_address) {
                // A signed-but-undecodable address must not wedge the
                // sender: keep paying the current working address.
                warn!(
                    "ack from {contact} carries an address that does not decode for this \
                     network; ratchet unchanged"
                );
                println!("ack received: accepted (next address invalid; ratchet unchanged)");
            } else if store::set_working_address(axion_dir, contact, &ack.next_address)? {
                println!(
                    "ack received: accepted; working address rotated to {}",
                    ack.next_address
                );
            } else {
                warn!("no stored peer entry for {contact}; cannot persist the rotated address");
                println!("ack received: accepted (address rotation not persisted)");
            }
        }
        // validate_ack only lets "accepted" | "invalid" through.
        _ => {
            if !store::set_outbox_status(axion_dir, contact, &txid, store::OutboxStatus::Rejected)?
            {
                warn!("ack from {contact} references txid {txid} with no matching outbox entry");
                return Ok(None);
            }
            println!("ack received: invalid; advice marked rejected in the outbox");
        }
    }
    Ok(Some(txid))
}

/// Mints the next available diversified unified address for the wallet's
/// account — the same machinery as `wallet generate-address` — and returns
/// its string encoding.
pub(crate) fn mint_next_address<P, DbT>(params: &P, db_data: &mut DbT) -> anyhow::Result<String>
where
    P: Parameters,
    DbT: WalletWrite<AccountId = AccountUuid>,
    DbT::Error: std::error::Error + Send + Sync + 'static,
{
    let account = crate::commands::select_account(db_data, None)?;
    let (ua, _) = db_data
        .get_next_available_address(account.id(), UnifiedAddressRequest::AllAvailableKeys)?
        .ok_or_else(|| anyhow!("the wallet account cannot generate a new diversified address"))?;
    Ok(ua.encode(params))
}

/// Waits until `deadline` for a message from `contact` whose JSON `type`
/// field is one of `wanted`, skipping unrelated chatter with a debug log.
/// Returns the matched type and raw text, or `None` once the deadline passes.
pub(crate) async fn wait_message_of_type(
    simplex: &mut SimplexClient,
    contact: &str,
    wanted: &[&str],
    deadline: Instant,
) -> anyhow::Result<Option<(String, String)>> {
    loop {
        let remaining = match deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
        {
            Some(remaining) => remaining,
            None => return Ok(None),
        };
        // `wait_text_from` reports its own timeout as an error; treat an
        // error that coincides with the deadline as the timeout it is.
        let text = match simplex.wait_text_from(contact, remaining).await {
            Ok(text) => text,
            Err(e) if Instant::now() >= deadline => {
                debug!("Treating wait error at deadline as timeout: {e}");
                return Ok(None);
            }
            Err(e) => return Err(e),
        };
        let kind = serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .and_then(|v| v.get("type").and_then(|t| t.as_str()).map(str::to_owned));
        match kind {
            Some(kind) if wanted.contains(&kind.as_str()) => return Ok(Some((kind, text))),
            _ => debug!("Ignoring message from {contact} while waiting for {wanted:?}: {text}"),
        }
    }
}

/// Parses a txid from its display-order hex representation (which is
/// byte-reversed relative to the in-memory encoding).
pub(crate) fn parse_txid(s: &str) -> anyhow::Result<TxId> {
    let bytes = hex::decode(s).map_err(|e| anyhow!("invalid txid hex: {e}"))?;
    let mut bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("txid must be 32 bytes (64 hex characters)"))?;
    bytes.reverse();
    Ok(TxId::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use ed25519_zebra::SigningKey;
    use secrecy::SecretVec;

    use super::{
        AckMessage, AdviceEnvelope, ack_message_signing_input, ack_status_byte,
        check_ack_signature, check_envelope_signature, decode_hex_array, envelope_signing_input,
        identity, parse_txid, pool_byte, validate_ack, validate_recovery_challenge,
        validate_recovery_proof, validate_redelivery_done, validate_token,
    };

    const TXID: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    fn test_signing_key() -> SigningKey {
        identity::derive_signing_key(&SecretVec::new(vec![7u8; 64]), 0)
    }

    fn stored_pubkey(sk: &SigningKey) -> String {
        hex::encode(identity::public_key_bytes(sk))
    }

    fn signed_envelope(sk: &SigningKey) -> AdviceEnvelope {
        let mut envelope = AdviceEnvelope {
            v: 1,
            kind: "advice".to_string(),
            txid: TXID.to_string(),
            height: 100,
            pool: "orchard".to_string(),
            output_index: 2,
            sig: None,
        };
        let sig = sk.sign(&envelope_signing_input(&envelope).unwrap());
        envelope.sig = Some(hex::encode(sig.to_bytes()));
        envelope
    }

    fn signed_ack(sk: &SigningKey, status: &str, next_address: &str) -> AckMessage {
        let mut ack = AckMessage {
            v: 1,
            kind: "ack".to_string(),
            txid: TXID.to_string(),
            status: status.to_string(),
            next_address: next_address.to_string(),
            counter: 1,
            sig: None,
        };
        let sig = sk.sign(&ack_message_signing_input(&ack).unwrap());
        ack.sig = Some(hex::encode(sig.to_bytes()));
        ack
    }

    #[test]
    fn parse_txid_round_trips_display_order() {
        let hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let txid = parse_txid(hex).unwrap();
        assert_eq!(txid.to_string(), hex);
    }

    #[test]
    fn parse_txid_rejects_bad_input() {
        assert!(parse_txid("abcd").is_err());
        assert!(
            parse_txid("zz112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").is_err()
        );
    }

    fn token_json(v: u32, kind: &str, pubkey: &str, sig: &str) -> String {
        format!(r#"{{"v":{v},"type":"{kind}","j":0,"pubkey":"{pubkey}","sig":"{sig}"}}"#)
    }

    #[test]
    fn validates_token_messages() {
        let pubkey = "ab".repeat(32);
        let sig = "cd".repeat(64);
        let msg = validate_token(&token_json(1, "token", &pubkey, &sig)).unwrap();
        assert_eq!(msg.j, 0);
        assert_eq!(msg.pubkey, pubkey);

        assert!(validate_token("not json").is_err());
        assert!(validate_token(&token_json(2, "token", &pubkey, &sig)).is_err());
        assert!(validate_token(&token_json(1, "advice", &pubkey, &sig)).is_err());
        assert!(validate_token(&token_json(1, "token", "abcd", &sig)).is_err());
        assert!(validate_token(&token_json(1, "token", &pubkey, "zz")).is_err());
    }

    #[test]
    fn validates_recovery_challenge_messages() {
        let nonce = "0f".repeat(32);
        let good = format!(r#"{{"v":1,"type":"recovery_challenge","nonce":"{nonce}"}}"#);
        assert_eq!(validate_recovery_challenge(&good).unwrap().nonce, nonce);

        let bad_nonce = r#"{"v":1,"type":"recovery_challenge","nonce":"1234"}"#;
        assert!(validate_recovery_challenge(bad_nonce).is_err());
        let bad_version = format!(r#"{{"v":0,"type":"recovery_challenge","nonce":"{nonce}"}}"#);
        assert!(validate_recovery_challenge(&bad_version).is_err());
    }

    #[test]
    fn validates_recovery_proof_messages() {
        let pubkey = "ab".repeat(32);
        let sig = "cd".repeat(64);
        let good =
            format!(r#"{{"v":1,"type":"recovery_proof","j":2,"pubkey":"{pubkey}","sig":"{sig}"}}"#);
        let msg = validate_recovery_proof(&good).unwrap();
        assert_eq!(msg.j, 2);

        let wrong_kind =
            format!(r#"{{"v":1,"type":"token","j":2,"pubkey":"{pubkey}","sig":"{sig}"}}"#);
        assert!(validate_recovery_proof(&wrong_kind).is_err());
        let short_sig =
            format!(r#"{{"v":1,"type":"recovery_proof","j":2,"pubkey":"{pubkey}","sig":"00"}}"#);
        assert!(validate_recovery_proof(&short_sig).is_err());
    }

    #[test]
    fn validates_redelivery_done_messages() {
        let msg = validate_redelivery_done(r#"{"v":1,"type":"redelivery_done","count":3}"#);
        assert_eq!(msg.unwrap().count, 3);
        assert!(validate_redelivery_done(r#"{"v":1,"type":"advice","count":3}"#).is_err());
        assert!(validate_redelivery_done(r#"{"v":7,"type":"redelivery_done","count":3}"#).is_err());
    }

    #[test]
    fn decodes_fixed_length_hex() {
        assert_eq!(decode_hex_array::<2>("beef").unwrap(), [0xbe, 0xef]);
        assert!(decode_hex_array::<2>("be").is_err());
        assert!(decode_hex_array::<2>("zzzz").is_err());
    }

    #[test]
    fn validates_token_address_field() {
        let pubkey = "ab".repeat(32);
        let sig = "cd".repeat(64);
        let with_address = format!(
            r#"{{"v":1,"type":"token","j":0,"pubkey":"{pubkey}","address":"uregtest1demo","sig":"{sig}"}}"#
        );
        let msg = validate_token(&with_address).unwrap();
        assert_eq!(msg.address.as_deref(), Some("uregtest1demo"));

        // Old tokens have no address field at all.
        let without =
            format!(r#"{{"v":1,"type":"token","j":0,"pubkey":"{pubkey}","sig":"{sig}"}}"#);
        assert_eq!(validate_token(&without).unwrap().address, None);

        let empty = format!(
            r#"{{"v":1,"type":"token","j":0,"pubkey":"{pubkey}","address":"","sig":"{sig}"}}"#
        );
        assert!(validate_token(&empty).is_err());
    }

    fn ack_json(v: u32, kind: &str, txid: &str, status: &str, sig: &str) -> String {
        format!(
            r#"{{"v":{v},"type":"{kind}","txid":"{txid}","status":"{status}","next_address":"uregtest1next","counter":1,"sig":"{sig}"}}"#
        )
    }

    #[test]
    fn validates_ack_messages() {
        let sig = "cd".repeat(64);
        let msg = validate_ack(&ack_json(1, "ack", TXID, "accepted", &sig)).unwrap();
        assert_eq!(msg.status, "accepted");
        assert_eq!(msg.next_address, "uregtest1next");
        assert!(validate_ack(&ack_json(1, "ack", TXID, "invalid", &sig)).is_ok());

        assert!(validate_ack("not json").is_err());
        assert!(validate_ack(&ack_json(2, "ack", TXID, "accepted", &sig)).is_err());
        assert!(validate_ack(&ack_json(1, "advice", TXID, "accepted", &sig)).is_err());
        assert!(validate_ack(&ack_json(1, "ack", "abcd", "accepted", &sig)).is_err());
        assert!(validate_ack(&ack_json(1, "ack", TXID, "maybe", &sig)).is_err());
        assert!(validate_ack(&ack_json(1, "ack", TXID, "accepted", "zz")).is_err());

        // An unsigned ack is well-formed (the signature policy decides what
        // to do with it).
        let unsigned = format!(
            r#"{{"v":1,"type":"ack","txid":"{TXID}","status":"accepted","next_address":"","counter":1}}"#
        );
        assert_eq!(validate_ack(&unsigned).unwrap().sig, None);
    }

    #[test]
    fn pool_and_status_bytes() {
        assert_eq!(pool_byte("sapling").unwrap(), 0);
        assert_eq!(pool_byte("orchard").unwrap(), 1);
        assert_eq!(pool_byte("ironwood").unwrap(), 2);
        assert!(pool_byte("transparent").is_err());
        assert_eq!(ack_status_byte("invalid").unwrap(), 0);
        assert_eq!(ack_status_byte("accepted").unwrap(), 1);
        assert!(ack_status_byte("maybe").is_err());
    }

    #[test]
    fn envelope_signature_policy() {
        let sk = test_signing_key();
        let pubkey = stored_pubkey(&sk);
        let envelope = signed_envelope(&sk);

        // Signed + stored key: must verify.
        assert!(check_envelope_signature(&envelope, Some(&pubkey)).is_ok());
        // Tampering any signed field breaks verification.
        for tamper in [
            |e: &mut AdviceEnvelope| {
                e.txid = format!("ff{}", &TXID[2..]);
            },
            |e: &mut AdviceEnvelope| e.height += 1,
            |e: &mut AdviceEnvelope| e.pool = "sapling".to_string(),
            |e: &mut AdviceEnvelope| e.output_index += 1,
        ] {
            let mut tampered = signed_envelope(&sk);
            tamper(&mut tampered);
            assert!(check_envelope_signature(&tampered, Some(&pubkey)).is_err());
        }
        // Wrong key stored.
        let other = stored_pubkey(&identity::derive_signing_key(
            &SecretVec::new(vec![8u8; 64]),
            0,
        ));
        assert!(check_envelope_signature(&envelope, Some(&other)).is_err());
        // Signed but no stored key: unverifiable, accepted.
        assert!(check_envelope_signature(&envelope, None).is_ok());
        // Unsigned: accepted with a warning either way.
        let mut unsigned = signed_envelope(&sk);
        unsigned.sig = None;
        assert!(check_envelope_signature(&unsigned, Some(&pubkey)).is_ok());
        assert!(check_envelope_signature(&unsigned, None).is_ok());
    }

    #[test]
    fn ack_signature_policy_guards_the_ratchet() {
        let sk = test_signing_key();
        let pubkey = stored_pubkey(&sk);
        let ack = signed_ack(&sk, "accepted", "uregtest1next");

        assert!(check_ack_signature(&ack, Some(&pubkey)).is_ok());
        // A corrupted signature must not drive a ratchet update.
        let mut bad_sig = signed_ack(&sk, "accepted", "uregtest1next");
        let mut sig_bytes = decode_hex_array::<64>(bad_sig.sig.as_deref().unwrap()).unwrap();
        sig_bytes[0] ^= 1;
        bad_sig.sig = Some(hex::encode(sig_bytes));
        assert!(check_ack_signature(&bad_sig, Some(&pubkey)).is_err());
        // Neither must a substituted next_address (the ratchet's whole point).
        let mut swapped = signed_ack(&sk, "accepted", "uregtest1next");
        swapped.next_address = "uregtest1evil".to_string();
        assert!(check_ack_signature(&swapped, Some(&pubkey)).is_err());
        // Nor a status flip.
        let mut flipped = signed_ack(&sk, "accepted", "uregtest1next");
        flipped.status = "invalid".to_string();
        assert!(check_ack_signature(&flipped, Some(&pubkey)).is_err());
        // Unsigned ack while a key is stored: unusable.
        let mut unsigned = signed_ack(&sk, "accepted", "uregtest1next");
        unsigned.sig = None;
        assert!(check_ack_signature(&unsigned, Some(&pubkey)).is_err());
        // Without a stored key acks are accepted (warned) — signed or not.
        assert!(check_ack_signature(&ack, None).is_ok());
        assert!(check_ack_signature(&unsigned, None).is_ok());
    }
}
