//! Long-term axion identity keys derived from the wallet's BIP-39 seed.
//!
//! Derivation:
//!   root = BLAKE2b-256(personal = "Zcash_AxionRoot", seed)
//!   k_j  = BLAKE2b-256(personal = "Zcash_AxionSubk", root || LE32(j))
//!
//! k_j is used directly as an Ed25519 signing key seed. Every signature is
//! domain-separated; pairing-time signatures are additionally channel-bound:
//! identity tokens sign "axion-token-v1" || LE32(j) || pubkey || H(link) ||
//! address, recovery proofs sign "axion-recovery-v1" || nonce || H(link),
//! where H(link) is a hash of the invitation link that created the channel
//! the message travels on. The binding makes a token or proof captured on one
//! channel worthless on any other (relay/MITM and cross-contact replay both
//! fail verification). Advice envelopes and acks are signed but NOT
//! channel-bound: they must survive re-delivery over a different channel
//! after recovery.

use anyhow::anyhow;
use ed25519_zebra::{Signature, SigningKey, VerificationKey};
use secrecy::{ExposeSecret, SecretVec, Zeroize};

use crate::config::WalletConfig;

const ROOT_PERSONAL: &[u8] = b"Zcash_AxionRoot";
const SUBKEY_PERSONAL: &[u8] = b"Zcash_AxionSubk";
const LINK_PERSONAL: &[u8] = b"Zcash_AxionLink";
const TOKEN_DOMAIN: &[u8] = b"axion-token-v1";
#[cfg(any(test, feature = "unstable-recovery"))]
const RECOVERY_DOMAIN: &[u8] = b"axion-recovery-v1";
const ADVICE_DOMAIN: &[u8] = b"axion-advice-v1";
const ACK_DOMAIN: &[u8] = b"axion-ack-v1";

fn blake2b_256(personal: &[u8], data: &[u8]) -> [u8; 32] {
    let hash = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(personal)
        .hash(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

/// Derives the identity subkey with index `j` from the BIP-39 wallet seed.
pub(crate) fn derive_signing_key(seed: &SecretVec<u8>, j: u32) -> SigningKey {
    let mut root = blake2b_256(ROOT_PERSONAL, seed.expose_secret());
    let mut input = [0u8; 36];
    input[..32].copy_from_slice(&root);
    input[32..].copy_from_slice(&j.to_le_bytes());
    let mut k_j = blake2b_256(SUBKEY_PERSONAL, &input);
    let sk = SigningKey::from(k_j);
    root.zeroize();
    input.zeroize();
    k_j.zeroize();
    sk
}

/// Reads the wallet config, decrypts its mnemonic with the given age identity
/// file, and derives identity subkey `j` from the resulting seed. The seed is
/// produced exactly the way `wallet init` does (BIP-39 with empty passphrase),
/// so a wallet restored from its phrase re-derives the same identity.
pub(crate) fn wallet_signing_key(
    wallet_dir: Option<&String>,
    identity_file: &str,
    j: u32,
) -> anyhow::Result<SigningKey> {
    let mut config = WalletConfig::read(wallet_dir)?;
    let identities = age::IdentityFile::from_file(identity_file.to_owned())?.into_identities()?;
    let seed = config
        .decrypt_seed(identities.iter().map(|i| i.as_ref() as _))?
        .ok_or_else(|| anyhow!("this wallet has no stored mnemonic to derive an identity from"))?;
    Ok(derive_signing_key(&seed, j))
}

/// Binding of a signature to the channel it travels on: a hash of the
/// invitation link that created that channel. Both ends know the link (one
/// minted it, the other joined it); a relay attacker cannot make two
/// different links hash alike.
pub(crate) fn link_binding(link: &str) -> [u8; 32] {
    blake2b_256(LINK_PERSONAL, link.as_bytes())
}

/// The domain-separated, channel-bound message an identity token's
/// self-signature covers. `address` is the UTF-8 of the token's optional
/// unified address field; tokens without one (all pre-address tokens, and
/// identity-only reply tokens) sign the empty slice, which keeps old-token
/// verification working unchanged.
pub(crate) fn token_signing_input(
    j: u32,
    pubkey: &[u8; 32],
    link: &[u8; 32],
    address: &[u8],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(TOKEN_DOMAIN.len() + 4 + 32 + 32 + address.len());
    msg.extend_from_slice(TOKEN_DOMAIN);
    msg.extend_from_slice(&j.to_le_bytes());
    msg.extend_from_slice(pubkey);
    msg.extend_from_slice(link);
    msg.extend_from_slice(address);
    msg
}

/// The domain-separated message an advice envelope's signature covers:
/// domain || txid (32 bytes, internal order) || height LE32 || pool byte
/// (0 = sapling, 1 = orchard, 2 = ironwood) || output index LE32.
/// Deliberately NOT channel-bound: advice must stay verifiable when it is
/// re-delivered over a different channel during recovery. The signature is a
/// property of the payment relationship, not of the transport.
pub(crate) fn advice_signing_input(
    txid: &[u8; 32],
    height: u32,
    pool: u8,
    output_index: u32,
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(ADVICE_DOMAIN.len() + 32 + 4 + 1 + 4);
    msg.extend_from_slice(ADVICE_DOMAIN);
    msg.extend_from_slice(txid);
    msg.extend_from_slice(&height.to_le_bytes());
    msg.push(pool);
    msg.extend_from_slice(&output_index.to_le_bytes());
    msg
}

/// The domain-separated message an acknowledgment's signature covers:
/// domain || txid (32 bytes, internal order) || status byte (0 = invalid,
/// 1 = accepted) || counter LE64 || next_address UTF-8 bytes. Like advice,
/// acks are NOT channel-bound: they belong to the payment relationship rather
/// than to any one channel (the channel's own double ratchet still
/// authenticates the transport hop). `counter` is a per-relationship monotonic
/// sequence the recipient advances on every ack it sends; the sender rejects
/// any signed ack whose counter is not strictly greater than the last it
/// accepted, so a captured ack cannot be replayed later to roll the working
/// address back to an older one.
pub(crate) fn ack_signing_input(
    txid: &[u8; 32],
    status: u8,
    counter: u64,
    next_address: &str,
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(ACK_DOMAIN.len() + 32 + 1 + 8 + next_address.len());
    msg.extend_from_slice(ACK_DOMAIN);
    msg.extend_from_slice(txid);
    msg.push(status);
    msg.extend_from_slice(&counter.to_le_bytes());
    msg.extend_from_slice(next_address.as_bytes());
    msg
}

/// The domain-separated, channel-bound message a recovery proof's signature
/// covers. Gated with recovery (see the `unstable-recovery` feature); kept
/// compiled under `test` so the domain-separation properties stay proven.
#[cfg(any(test, feature = "unstable-recovery"))]
pub(crate) fn recovery_signing_input(nonce: &[u8; 32], link: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(RECOVERY_DOMAIN.len() + 32 + 32);
    msg.extend_from_slice(RECOVERY_DOMAIN);
    msg.extend_from_slice(nonce);
    msg.extend_from_slice(link);
    msg
}

pub(crate) fn public_key_bytes(sk: &SigningKey) -> [u8; 32] {
    VerificationKey::from(sk).into()
}

pub(crate) fn verify_signature(
    pubkey: &[u8; 32],
    msg: &[u8],
    sig: &[u8; 64],
) -> anyhow::Result<()> {
    let vk = VerificationKey::try_from(*pubkey).map_err(|e| anyhow!("invalid public key: {e}"))?;
    vk.verify(&Signature::from_bytes(sig), msg)
        .map_err(|e| anyhow!("signature verification failed: {e}"))
}

#[cfg(test)]
mod tests {
    use secrecy::SecretVec;

    use super::{
        ack_signing_input, advice_signing_input, derive_signing_key, link_binding,
        public_key_bytes, recovery_signing_input, token_signing_input, verify_signature,
    };

    fn test_seed() -> SecretVec<u8> {
        SecretVec::new(vec![7u8; 64])
    }

    fn test_link() -> [u8; 32] {
        link_binding("simplex:/invitation#test-channel")
    }

    #[test]
    fn derivation_is_deterministic_and_index_separated() {
        let a = public_key_bytes(&derive_signing_key(&test_seed(), 0));
        let b = public_key_bytes(&derive_signing_key(&test_seed(), 0));
        let c = public_key_bytes(&derive_signing_key(&test_seed(), 1));
        let d = public_key_bytes(&derive_signing_key(&SecretVec::new(vec![8u8; 64]), 0));
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
    }

    #[test]
    fn token_signature_roundtrip_and_tamper_rejection() {
        let sk = derive_signing_key(&test_seed(), 0);
        let pubkey = public_key_bytes(&sk);
        let link = test_link();
        let sig = sk
            .sign(&token_signing_input(0, &pubkey, &link, b""))
            .to_bytes();

        assert!(
            verify_signature(&pubkey, &token_signing_input(0, &pubkey, &link, b""), &sig).is_ok()
        );
        // Wrong subkey index.
        assert!(
            verify_signature(&pubkey, &token_signing_input(1, &pubkey, &link, b""), &sig).is_err()
        );
        // Different channel: a token replayed on another invitation fails.
        let other_link = link_binding("simplex:/invitation#other-channel");
        assert!(
            verify_signature(
                &pubkey,
                &token_signing_input(0, &pubkey, &other_link, b""),
                &sig
            )
            .is_err()
        );
        // Tampered signature.
        let mut bad_sig = sig;
        bad_sig[0] ^= 1;
        assert!(
            verify_signature(
                &pubkey,
                &token_signing_input(0, &pubkey, &link, b""),
                &bad_sig
            )
            .is_err()
        );
        // Different key.
        let other = public_key_bytes(&derive_signing_key(&test_seed(), 1));
        assert!(
            verify_signature(&other, &token_signing_input(0, &pubkey, &link, b""), &sig).is_err()
        );
    }

    #[test]
    fn token_signature_covers_the_address() {
        let sk = derive_signing_key(&test_seed(), 0);
        let pubkey = public_key_bytes(&sk);
        let link = test_link();
        let addr = b"uregtest1demo".as_slice();
        let sig = sk
            .sign(&token_signing_input(0, &pubkey, &link, addr))
            .to_bytes();

        assert!(
            verify_signature(&pubkey, &token_signing_input(0, &pubkey, &link, addr), &sig).is_ok()
        );
        // Stripping or swapping the address invalidates the token.
        assert!(
            verify_signature(&pubkey, &token_signing_input(0, &pubkey, &link, b""), &sig).is_err()
        );
        assert!(
            verify_signature(
                &pubkey,
                &token_signing_input(0, &pubkey, &link, b"uregtest1other"),
                &sig
            )
            .is_err()
        );
        // An address-less token still verifies with the empty-slice input
        // (backwards compatibility with pre-address tokens).
        let old_sig = sk
            .sign(&token_signing_input(0, &pubkey, &link, b""))
            .to_bytes();
        assert!(
            verify_signature(
                &pubkey,
                &token_signing_input(0, &pubkey, &link, b""),
                &old_sig
            )
            .is_ok()
        );
    }

    #[test]
    fn advice_signature_tamper_rejection_per_field() {
        let sk = derive_signing_key(&test_seed(), 0);
        let pubkey = public_key_bytes(&sk);
        let txid = [9u8; 32];
        let sig = sk.sign(&advice_signing_input(&txid, 100, 1, 2)).to_bytes();

        assert!(verify_signature(&pubkey, &advice_signing_input(&txid, 100, 1, 2), &sig).is_ok());
        // Tampered txid.
        let mut other_txid = txid;
        other_txid[0] ^= 1;
        assert!(
            verify_signature(&pubkey, &advice_signing_input(&other_txid, 100, 1, 2), &sig).is_err()
        );
        // Tampered height.
        assert!(verify_signature(&pubkey, &advice_signing_input(&txid, 101, 1, 2), &sig).is_err());
        // Tampered pool byte.
        assert!(verify_signature(&pubkey, &advice_signing_input(&txid, 100, 0, 2), &sig).is_err());
        // Tampered output index.
        assert!(verify_signature(&pubkey, &advice_signing_input(&txid, 100, 1, 3), &sig).is_err());
        // Cross-domain: an ack signature over the same txid never verifies as
        // advice.
        let cross = sk.sign(&ack_signing_input(&txid, 1, 0, "")).to_bytes();
        assert!(
            verify_signature(&pubkey, &advice_signing_input(&txid, 100, 1, 2), &cross).is_err()
        );
    }

    #[test]
    fn ack_signature_tamper_rejection_per_field() {
        let sk = derive_signing_key(&test_seed(), 0);
        let pubkey = public_key_bytes(&sk);
        let txid = [5u8; 32];
        let addr = "uregtest1next";
        let sig = sk.sign(&ack_signing_input(&txid, 1, 7, addr)).to_bytes();

        assert!(verify_signature(&pubkey, &ack_signing_input(&txid, 1, 7, addr), &sig).is_ok());
        // Flipped status byte: an accepted-ack cannot be replayed as invalid.
        assert!(verify_signature(&pubkey, &ack_signing_input(&txid, 0, 7, addr), &sig).is_err());
        // Tampered counter: a captured ack cannot be re-stamped with a newer
        // sequence number to bypass the sender's replay check.
        assert!(verify_signature(&pubkey, &ack_signing_input(&txid, 1, 8, addr), &sig).is_err());
        // Tampered txid.
        let mut other_txid = txid;
        other_txid[31] ^= 1;
        assert!(
            verify_signature(&pubkey, &ack_signing_input(&other_txid, 1, 7, addr), &sig).is_err()
        );
        // Tampered or stripped next_address: the ratchet address cannot be
        // substituted in transit.
        assert!(
            verify_signature(
                &pubkey,
                &ack_signing_input(&txid, 1, 7, "uregtest1evil"),
                &sig
            )
            .is_err()
        );
        assert!(verify_signature(&pubkey, &ack_signing_input(&txid, 1, 7, ""), &sig).is_err());
    }

    #[test]
    fn recovery_signature_roundtrip_and_tamper_rejection() {
        let sk = derive_signing_key(&test_seed(), 0);
        let pubkey = public_key_bytes(&sk);
        let nonce = [42u8; 32];
        let link = test_link();
        let sig = sk.sign(&recovery_signing_input(&nonce, &link)).to_bytes();

        assert!(verify_signature(&pubkey, &recovery_signing_input(&nonce, &link), &sig).is_ok());
        let mut other_nonce = nonce;
        other_nonce[31] ^= 1;
        assert!(
            verify_signature(&pubkey, &recovery_signing_input(&other_nonce, &link), &sig).is_err()
        );
        // A proof relayed onto a different channel fails: the signature binds
        // the invitation link of the channel it was created for.
        let other_link = link_binding("simplex:/invitation#other-channel");
        assert!(
            verify_signature(&pubkey, &recovery_signing_input(&nonce, &other_link), &sig).is_err()
        );
        // A token signature must never verify as a recovery proof, even over
        // matching payload bytes: the domains are separated.
        let cross = sk
            .sign(&token_signing_input(0, &pubkey, &link, b""))
            .to_bytes();
        assert!(verify_signature(&pubkey, &recovery_signing_input(&nonce, &link), &cross).is_err());
    }
}
