//! Sender-side persistent state for the axion advice protocol: paired peer
//! identities (`axion-peers.json`) and the outbox of previously sent advice
//! envelopes (`axion-outbox.json`), kept as JSON files in the wallet
//! directory.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::anyhow;
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

const PEERS_FILE: &str = "axion-peers.json";
const OUTBOX_FILE: &str = "axion-outbox.json";
const INDEX_FILE: &str = "axion-next-index.json";

/// A peer's long-term identity as learned at pairing time: the subkey index
/// and the hex-encoded Ed25519 public key of its identity token, plus the
/// mutable relationship state — `working_address` is the address this wallet
/// currently pays the peer at (ratcheted forward by accepted-acks), and
/// `my_index` records which of OUR OWN subkey indexes this relationship uses
/// (allocated at pair time; `advice receive`/`send` sign with it).
/// `next_ack_counter` (payee side) is the next value to stamp on an outgoing
/// ack; `last_ack_counter` (payer side) is the highest counter accepted from
/// the peer, which drives the replay guard. All are optional so entries written
/// before each field existed still load.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct PeerIdentity {
    pub(crate) j: u32,
    pub(crate) pubkey: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) working_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) my_index: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) next_ack_counter: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) last_ack_counter: Option<u64>,
}

/// Delivery state of one outbox entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum OutboxStatus {
    Pending,
    Acked,
    Rejected,
}

/// One sent advice with its acknowledgment state. Re-delivery replays the
/// envelope of every entry regardless of status: a recovered wallet needs
/// everything it was ever advised about.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct OutboxEntry {
    pub(crate) envelope: serde_json::Value,
    pub(crate) status: OutboxStatus,
    /// Unix seconds when the advice was first sent. None on entries written
    /// before timestamps were recorded; `advice flush` reports such entries
    /// as overdue-with-unknown-age rather than silently fresh.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) sent_at: Option<u64>,
}

impl OutboxEntry {
    /// The display-order txid hex the envelope carries, if any. Central so the
    /// field name and the case-insensitive matching intent live in one place.
    pub(crate) fn txid(&self) -> Option<&str> {
        self.envelope.get("txid").and_then(|t| t.as_str())
    }
}

/// Loader-side compatibility shim: older outboxes stored bare envelope
/// values. Serde tries the structured entry first (it requires the
/// `envelope` and `status` fields), so a bare envelope falls through to the
/// legacy arm and loads as pending.
#[derive(Deserialize)]
#[serde(untagged)]
enum OutboxEntryCompat {
    Entry(OutboxEntry),
    Legacy(serde_json::Value),
}

impl From<OutboxEntryCompat> for OutboxEntry {
    fn from(compat: OutboxEntryCompat) -> Self {
        match compat {
            OutboxEntryCompat::Entry(entry) => entry,
            OutboxEntryCompat::Legacy(envelope) => OutboxEntry {
                envelope,
                status: OutboxStatus::Pending,
                sent_at: None,
            },
        }
    }
}

/// The axion state files live in the wallet directory. Unlike the wallet
/// database there is no default-directory fallback: recovery-critical state
/// must land where the operator explicitly pointed.
pub(crate) fn require_wallet_dir(wallet_dir: Option<&String>) -> anyhow::Result<PathBuf> {
    wallet_dir.map(PathBuf::from).ok_or_else(|| {
        anyhow!("this command stores axion state in the wallet directory; pass -w/--wallet-dir")
    })
}

fn load_map<T: DeserializeOwned>(path: &Path) -> anyhow::Result<BTreeMap<String, T>> {
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    let contents = fs::read_to_string(path)?;
    serde_json::from_str(&contents).map_err(|e| anyhow!("corrupt {}: {e}", path.display()))
}

/// Atomically replaces `path`'s contents (write-then-rename): a crash mid-write
/// must not corrupt recovery-critical state, since a half-written JSON file
/// would fail every future load.
fn atomic_write(path: &Path, contents: &str) -> anyhow::Result<()> {
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, contents)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

fn store_map<T: Serialize>(path: &Path, map: &BTreeMap<String, T>) -> anyhow::Result<()> {
    atomic_write(path, &serde_json::to_string_pretty(map)?)
}

/// Allocates the next unused identity subkey index for a new pairing and
/// persists its successor, so every contact gets a distinct verification key
/// (spec 1.3.5: leaked sender records must share no common identifier). The
/// counter starts at a random offset the first time it is created: a wallet
/// restored from seed alone has no record of the indexes it issued before, so
/// resuming at a fresh random point makes reissuing an old index negligibly
/// unlikely (the full index-to-contact map is restored separately by the
/// Step 3 encrypted backup).
pub(crate) fn allocate_identity_index(wallet_dir: &Path) -> anyhow::Result<u32> {
    let path = wallet_dir.join(INDEX_FILE);
    let next = if path.exists() {
        serde_json::from_str::<u32>(&fs::read_to_string(&path)?)
            .map_err(|e| anyhow!("corrupt {}: {e}", path.display()))?
    } else {
        // Keep the high bit clear so the sequence can advance without wrapping.
        let mut buf = [0u8; 4];
        OsRng.fill_bytes(&mut buf);
        u32::from_le_bytes(buf) & 0x7fff_ffff
    };
    let successor = next
        .checked_add(1)
        .ok_or_else(|| anyhow!("identity index space exhausted"))?;
    atomic_write(&path, &serde_json::to_string(&successor)?)?;
    Ok(next)
}

/// Returns the next per-relationship counter to stamp on an outgoing ack to
/// `contact`, advancing the stored monotonic sequence so the sender can reject
/// replays. Falls back to a transient `1` when no peer entry exists: without a
/// stored peer key the sender cannot verify the ack, so the counter is not
/// enforced there anyway.
pub(crate) fn next_outgoing_counter(wallet_dir: &Path, contact: &str) -> anyhow::Result<u64> {
    let path = wallet_dir.join(PEERS_FILE);
    let mut peers: BTreeMap<String, PeerIdentity> = load_map(&path)?;
    match peers.get_mut(contact) {
        Some(peer) => {
            let counter = peer.next_ack_counter.unwrap_or(1);
            peer.next_ack_counter = Some(
                counter
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("ack counter space exhausted"))?,
            );
            store_map(&path, &peers)?;
            Ok(counter)
        }
        None => Ok(1),
    }
}

/// Records the counter of a signature-valid ack received from `contact`,
/// returning true when it is strictly newer than the last accepted (persisting
/// the new high-water mark) or false when it is a replayed/stale value the
/// caller must ignore. A no-op returning true when no peer entry is stored (the
/// unverifiable case, where nothing is enforced).
pub(crate) fn accept_incoming_counter(
    wallet_dir: &Path,
    contact: &str,
    counter: u64,
) -> anyhow::Result<bool> {
    let path = wallet_dir.join(PEERS_FILE);
    let mut peers: BTreeMap<String, PeerIdentity> = load_map(&path)?;
    match peers.get_mut(contact) {
        Some(peer) => {
            if peer.last_ack_counter.is_some_and(|last| counter <= last) {
                return Ok(false);
            }
            peer.last_ack_counter = Some(counter);
            store_map(&path, &peers)?;
            Ok(true)
        }
        None => Ok(true),
    }
}

pub(crate) fn load_peers(wallet_dir: &Path) -> anyhow::Result<BTreeMap<String, PeerIdentity>> {
    load_map(&wallet_dir.join(PEERS_FILE))
}

pub(crate) fn save_peer(
    wallet_dir: &Path,
    contact: &str,
    peer: PeerIdentity,
) -> anyhow::Result<()> {
    let path = wallet_dir.join(PEERS_FILE);
    let mut peers: BTreeMap<String, PeerIdentity> = load_map(&path)?;
    // One identity key belongs to one contact: a token presenting a key
    // already stored under a different name is a replay attempt, and
    // accepting it would make later recovery matches ambiguous.
    if let Some((other, _)) = peers
        .iter()
        .find(|(name, existing)| *name != contact && existing.pubkey == peer.pubkey)
    {
        return Err(anyhow!(
            "identity key is already bound to contact {other:?}; refusing to store it for \
             {contact:?}"
        ));
    }
    peers.insert(contact.to_owned(), peer);
    store_map(&path, &peers)
}

/// Updates the working address of an already-paired contact. Returns false
/// (leaving the file untouched) when the contact has no stored entry: without
/// its identity there is nowhere to hang relationship state.
pub(crate) fn set_working_address(
    wallet_dir: &Path,
    contact: &str,
    address: &str,
) -> anyhow::Result<bool> {
    let path = wallet_dir.join(PEERS_FILE);
    let mut peers: BTreeMap<String, PeerIdentity> = load_map(&path)?;
    match peers.get_mut(contact) {
        Some(peer) => {
            peer.working_address = Some(address.to_owned());
            store_map(&path, &peers)?;
            Ok(true)
        }
        None => Ok(false),
    }
}

pub(crate) fn load_outbox(wallet_dir: &Path) -> anyhow::Result<BTreeMap<String, Vec<OutboxEntry>>> {
    let compat: BTreeMap<String, Vec<OutboxEntryCompat>> = load_map(&wallet_dir.join(OUTBOX_FILE))?;
    Ok(compat
        .into_iter()
        .map(|(contact, entries)| (contact, entries.into_iter().map(Into::into).collect()))
        .collect())
}

pub(crate) fn append_outbox(
    wallet_dir: &Path,
    contact: &str,
    envelope: serde_json::Value,
) -> anyhow::Result<()> {
    let path = wallet_dir.join(OUTBOX_FILE);
    let mut outbox = load_outbox(wallet_dir)?;
    // A clock reading before the Unix epoch yields no timestamp; the entry
    // is then reported by `advice flush` as overdue-with-unknown-age instead
    // of failing the send.
    let sent_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs());
    outbox
        .entry(contact.to_owned())
        .or_default()
        .push(OutboxEntry {
            envelope,
            status: OutboxStatus::Pending,
            sent_at,
        });
    store_map(&path, &outbox)
}

/// Marks every outbox entry for `contact` whose envelope carries `txid` with
/// the given status. Returns false when nothing matched.
pub(crate) fn set_outbox_status(
    wallet_dir: &Path,
    contact: &str,
    txid: &str,
    status: OutboxStatus,
) -> anyhow::Result<bool> {
    let path = wallet_dir.join(OUTBOX_FILE);
    let mut outbox = load_outbox(wallet_dir)?;
    let mut updated = false;
    if let Some(entries) = outbox.get_mut(contact) {
        for entry in entries.iter_mut() {
            // Compare case-insensitively: an entry written by a pre-txid-
            // normalization build could carry uppercase hex, and the caller
            // works with the lowercased ack txid — an exact compare would
            // silently never match and leave the entry pending forever.
            let matches = entry.txid().is_some_and(|t| t.eq_ignore_ascii_case(txid));
            if matches {
                entry.status = status;
                updated = true;
            }
        }
    }
    if updated {
        store_map(&path, &outbox)?;
    }
    Ok(updated)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        OutboxStatus, PeerIdentity, accept_incoming_counter, allocate_identity_index,
        append_outbox, load_outbox, load_peers, next_outgoing_counter, save_peer,
        set_outbox_status, set_working_address,
    };

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "zcash-devtool-axion-store-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn peer(j: u32, pubkey: String) -> PeerIdentity {
        PeerIdentity {
            j,
            pubkey,
            working_address: None,
            my_index: None,
            next_ack_counter: None,
            last_ack_counter: None,
        }
    }

    #[test]
    fn peers_roundtrip() {
        let dir = temp_dir("peers");
        assert!(load_peers(&dir).unwrap().is_empty());

        save_peer(
            &dir,
            "alice",
            PeerIdentity {
                j: 0,
                pubkey: "aa".repeat(32),
                working_address: Some("uregtest1demo".to_string()),
                my_index: Some(4),
                next_ack_counter: None,
                last_ack_counter: None,
            },
        )
        .unwrap();
        save_peer(&dir, "carol", peer(3, "bb".repeat(32))).unwrap();

        let peers = load_peers(&dir).unwrap();
        assert_eq!(peers.len(), 2);
        assert_eq!(peers["alice"].j, 0);
        assert_eq!(peers["alice"].pubkey, "aa".repeat(32));
        assert_eq!(
            peers["alice"].working_address.as_deref(),
            Some("uregtest1demo")
        );
        assert_eq!(peers["alice"].my_index, Some(4));
        assert_eq!(peers["carol"].j, 3);
        assert_eq!(peers["carol"].working_address, None);
        assert_eq!(peers["carol"].my_index, None);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn old_format_peers_load_with_empty_relationship_state() {
        let dir = temp_dir("peers-old");
        // An entry written before working_address/my_index existed.
        std::fs::write(
            dir.join("axion-peers.json"),
            format!(
                r#"{{"alice": {{"j": 2, "pubkey": "{}"}}}}"#,
                "aa".repeat(32)
            ),
        )
        .unwrap();

        let peers = load_peers(&dir).unwrap();
        assert_eq!(peers["alice"].j, 2);
        assert_eq!(peers["alice"].working_address, None);
        assert_eq!(peers["alice"].my_index, None);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn refuses_duplicate_pubkey_under_a_different_contact() {
        let dir = temp_dir("peers-dup");
        save_peer(&dir, "alice", peer(0, "aa".repeat(32))).unwrap();
        // Same key under a different name is refused...
        assert!(save_peer(&dir, "mallory", peer(0, "aa".repeat(32))).is_err());
        // ...but re-storing under the same name (re-pairing) is fine.
        save_peer(&dir, "alice", peer(1, "aa".repeat(32))).unwrap();
        assert_eq!(load_peers(&dir).unwrap()["alice"].j, 1);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn working_address_updates_only_known_contacts() {
        let dir = temp_dir("peers-addr");
        save_peer(&dir, "alice", peer(0, "aa".repeat(32))).unwrap();

        assert!(set_working_address(&dir, "alice", "uregtest1next").unwrap());
        assert_eq!(
            load_peers(&dir).unwrap()["alice"]
                .working_address
                .as_deref(),
            Some("uregtest1next")
        );
        // Unknown contact: no entry to update, file untouched.
        assert!(!set_working_address(&dir, "nobody", "uregtest1next").unwrap());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn outbox_append_preserves_order_and_starts_pending() {
        let dir = temp_dir("outbox");
        assert!(load_outbox(&dir).unwrap().is_empty());

        let first = json!({"v": 1, "type": "advice", "txid": "00", "height": 5});
        let second = json!({"v": 1, "type": "advice", "txid": "11", "height": 6});
        append_outbox(&dir, "alice", first.clone()).unwrap();
        append_outbox(&dir, "alice", second.clone()).unwrap();
        append_outbox(&dir, "carol", first.clone()).unwrap();

        let outbox = load_outbox(&dir).unwrap();
        assert_eq!(
            outbox["alice"]
                .iter()
                .map(|e| e.envelope.clone())
                .collect::<Vec<_>>(),
            vec![first.clone(), second]
        );
        assert!(
            outbox["alice"]
                .iter()
                .all(|e| e.status == OutboxStatus::Pending)
        );
        assert_eq!(outbox["carol"][0].envelope, first);

        // Every appended entry records when it was sent.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        for entry in outbox.values().flatten() {
            let sent_at = entry.sent_at.expect("append_outbox records sent_at");
            assert!(sent_at <= now && sent_at + 60 > now);
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn old_format_outbox_loads_as_pending() {
        let dir = temp_dir("outbox-old");
        // Bare envelope values, the pre-status format.
        std::fs::write(
            dir.join("axion-outbox.json"),
            r#"{"alice": [{"v": 1, "type": "advice", "txid": "00", "height": 5}]}"#,
        )
        .unwrap();

        let outbox = load_outbox(&dir).unwrap();
        assert_eq!(outbox["alice"].len(), 1);
        assert_eq!(outbox["alice"][0].status, OutboxStatus::Pending);
        assert_eq!(outbox["alice"][0].envelope["txid"], "00");
        assert_eq!(outbox["alice"][0].sent_at, None);

        // Appending re-writes the file in the new format without losing the
        // legacy entry.
        append_outbox(
            &dir,
            "alice",
            json!({"v": 1, "type": "advice", "txid": "11"}),
        )
        .unwrap();
        let outbox = load_outbox(&dir).unwrap();
        assert_eq!(outbox["alice"].len(), 2);
        assert_eq!(outbox["alice"][0].envelope["txid"], "00");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn structured_entries_without_sent_at_load_as_none() {
        let dir = temp_dir("outbox-no-sent-at");
        // A structured `{envelope, status}` entry written before sent_at
        // existed must still load, with an unknown send time.
        std::fs::write(
            dir.join("axion-outbox.json"),
            r#"{"alice": [{"envelope": {"v": 1, "type": "advice", "txid": "00"}, "status": "acked"}]}"#,
        )
        .unwrap();

        let outbox = load_outbox(&dir).unwrap();
        assert_eq!(outbox["alice"][0].status, OutboxStatus::Acked);
        assert_eq!(outbox["alice"][0].sent_at, None);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn outbox_status_updates_by_txid() {
        let dir = temp_dir("outbox-status");
        append_outbox(
            &dir,
            "alice",
            json!({"v": 1, "type": "advice", "txid": "00"}),
        )
        .unwrap();
        append_outbox(
            &dir,
            "alice",
            json!({"v": 1, "type": "advice", "txid": "11"}),
        )
        .unwrap();

        assert!(set_outbox_status(&dir, "alice", "11", OutboxStatus::Acked).unwrap());
        let outbox = load_outbox(&dir).unwrap();
        assert_eq!(outbox["alice"][0].status, OutboxStatus::Pending);
        assert_eq!(outbox["alice"][1].status, OutboxStatus::Acked);

        // No matching txid or contact: nothing changes.
        assert!(!set_outbox_status(&dir, "alice", "ff", OutboxStatus::Acked).unwrap());
        assert!(!set_outbox_status(&dir, "bob", "00", OutboxStatus::Acked).unwrap());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn identity_index_allocation_is_monotonic_and_persisted() {
        let dir = temp_dir("index-alloc");
        let first = allocate_identity_index(&dir).unwrap();
        let second = allocate_identity_index(&dir).unwrap();
        let third = allocate_identity_index(&dir).unwrap();
        // Distinct and strictly increasing, so no two contacts share a key.
        assert_eq!(second, first + 1);
        assert_eq!(third, first + 2);
        // The successor survives across processes (persisted to disk), so a
        // later allocation never reuses an index.
        assert!(allocate_identity_index(&dir).unwrap() > third);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn outgoing_counter_advances_and_incoming_counter_rejects_replays() {
        let dir = temp_dir("counters");
        save_peer(&dir, "alice", peer(0, "aa".repeat(32))).unwrap();

        // The payee side hands out a strictly increasing sequence per contact.
        assert_eq!(next_outgoing_counter(&dir, "alice").unwrap(), 1);
        assert_eq!(next_outgoing_counter(&dir, "alice").unwrap(), 2);
        // Without a stored peer entry it falls back to a transient value.
        assert_eq!(next_outgoing_counter(&dir, "nobody").unwrap(), 1);

        // The payer side accepts only strictly newer counters.
        assert!(accept_incoming_counter(&dir, "alice", 5).unwrap());
        // A replay (equal) and a stale (older) counter are both rejected,
        // leaving the high-water mark untouched.
        assert!(!accept_incoming_counter(&dir, "alice", 5).unwrap());
        assert!(!accept_incoming_counter(&dir, "alice", 4).unwrap());
        // A newer one advances it.
        assert!(accept_incoming_counter(&dir, "alice", 6).unwrap());
        assert!(!accept_incoming_counter(&dir, "alice", 6).unwrap());
        // An unknown contact is a no-op that never enforces (unverifiable).
        assert!(accept_incoming_counter(&dir, "nobody", 1).unwrap());

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
