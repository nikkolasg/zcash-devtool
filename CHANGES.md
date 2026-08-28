# CHANGES

## Recovery disabled behind `unstable-recovery`

`advice recover`/`redeliver` and the four recovery wire messages are compiled
out of default builds (cargo feature `unstable-recovery`, off by default).
With per-contact identity indices, honest seed-only recovery needs the
index↔contact map restored by the future Step 3 encrypted backup; until then
the flow only works when the operator supplies an index a real user would have
lost. The code and its tests stay in the tree (validators and the recovery
signing input remain test-compiled), so the protocol stays proven and
re-enabling is a feature flag, not a rewrite. Payments are unaffected: the
chain rail finds everything by normal scanning.

## Removed `advice rotate` and `advice contact`

Trimmed the subcommand surface to pair/send/receive/flush/redeliver/recover.
`advice rotate` (recipient-initiated address rotation, spec 1.3.5) and its whole
message path — `RotateMessage`, `validate_rotate`, `check_rotate_signature`,
`process_rotate_message`, `rotate_signing_input`, the `ROTATE_DOMAIN`, and the
`"rotate"` branches in `send`/`flush`'s ack waits — are gone, since nothing
produces rotations anymore. The primary address ratchet (each accepted ack
carries the next address, spec 1.3.3) is unaffected. `advice contact` (a JSON
introspection wrapper) is gone too.

## Per-contact identity index + ack replay counter

Pairing now allocates a fresh identity subkey index per contact (`advice pair`
without `--index` draws the next value from `axion-next-index.json`, which
starts at a random offset so a seed-only recovery cannot reissue an old index),
so two senders' stored records share no common verification key — closing a
linkability gap against spec 1.3.5 / demo scenario 3. `--index` became an
override (was a default of `0`, which handed every contact the same key).
`advice recover --index <j>` must now supply the index the relationship was
paired with (restored by Step 3's encrypted backup in the full product), since
seed-only recovery no longer knows it. `send`/`receive`/`rotate` are unchanged —
they already prefer the stored `my_index`.

Acks now carry a per-relationship monotonic `counter` in their signed bytes:
the recipient advances the sequence (`next_ack_counter`), and the sender ignores
any signature-valid ack whose counter is not strictly greater than the last it
accepted (`last_ack_counter`), so a captured ack can no longer be replayed to
roll the working address back to an older one. The `AckMessage` wire format grew
a required `counter` field (pre-release; no wire back-compat). Stored peer
entries grew the two counters (old files still load).

## `advice receive` privacy-claim wording

The default path's comments no longer claim a byte-identical indexer
fingerprint. It issues the same block-download requests a sync makes (so the
advised note is never revealed to the indexer) but front-loads them and skips
the transparent-UTXO refresh, so an indexer can still tell a receive from a full
sync — it just never learns which transaction or note is the recipient's.

## Private `advice receive` (no indexer leak)

`advice receive` no longer fetches the advised transaction with
`GetTransaction` by default — that revealed the exact txid to the
lightwalletd/zaino indexer, a privacy regression versus compact-block
scanning. The default path now makes the same network requests a normal
syncing wallet makes (subtree roots, chain tip, and an ordinary full-range
`GetBlockRange` over the scan gap, cached in `FsBlockDb`), then decrypts
purely locally: a "priority peek" trial-decrypts only the advised block from
cache (via `scan_block`, no note-commitment-tree state, no network) for
instant visibility, then a full-gap `scan_cached_blocks` runs to completion
so nothing else is missed and the advised note is durably stored with its
witness. The indexer sees an identical fingerprint and never learns which
tx/note is the recipient's. The old single-tx behavior is kept behind
`--fast-sync` (lower privacy). Envelope-signature policy, the ack/address
ratchet, and reject paths are unchanged.

The shared sync primitives (`update_subtree_roots`, `update_chain_tip`,
`download_blocks`, `download_chain_state`, `delete_cached_blocks`) were
hoisted from `wallet sync` into `helpers/scan.rs` so both commands issue the
same requests; `download_blocks` takes a per-block callback so `sync` keeps
its TUI/shutdown handling. `advice recover` still uses `GetTransaction` per
advice (it runs on a rescanning wallet) — marked with a `TODO(privacy)`.

## Retention-sweep review fixes

Adversarial review of flush/rotate: fixed batched `newChatItems` handling
in simplex.rs (a single event can carry several queued messages on
reconnect — the flush case; all are now buffered instead of dropping all
but the first, so one flush resolves multiple acks), made outbox txid
matching case-insensitive with a warn on no-match (was a silent no-op that
could re-send an entry forever), and connect to SimpleX before minting a
rotation address (a failed connection no longer burns a diversifier).

## Re-send loop and recipient-initiated rotation (spec 1.3.2 / 1.3.5)

`advice flush --ws --to [--ack-timeout 30] [--overdue-secs 86400]` is the
sender-side re-send loop: prints an outbox summary, an `OVERDUE:` line per
pending entry older than `--overdue-secs` (entries from before timestamps
count as overdue, age unknown), re-sends every pending envelope verbatim,
then processes acks until timeout or all resolved. `advice rotate --ws --to
--identity [--index]` is the recipient side: mints the next diversified
address and sends a signed `rotate` message (`axion-rotate-v1 || address`,
not channel-bound, same replay caveat as acks — sender verification requires
the stored peer key). Rotate messages are also handled during `send`'s ack
wait and `flush` (shared `process_ack_message`/`process_rotate_message` in
advice.rs). Outbox entries now record `sent_at` (unix secs); old files load
with `None`.

## Signed envelopes, acks, and the address ratchet (spec 1.3.3)

Pairing is now bidirectional: `pair --mode invite` mints a fresh diversified
address (same machinery as `wallet generate-address`) and ships it inside its
token (`address` field, covered by the token signature via empty-slice
back-compat); `pair --mode join` stores it as the contact's `working_address`
and replies with an identity-only token of its own. `advice send --identity`
signs envelopes (`sig` field; input `axion-advice-v1 || txid || height_le ||
pool_byte || index_le`, deliberately NOT channel-bound so re-delivered advice
still verifies) and waits `--ack-timeout` for a signed ack; `advice receive
--identity` verifies the envelope against the stored peer key (hard reject on
mismatch; missing sig/key only warns) and answers with a signed accepted-ack
carrying the NEXT fresh address, which rotates the sender's stored
`working_address` (`advice contact --to <name>` prints it for scripts).
Rejections best-effort send an invalid-ack first. Store formats grew
(`working_address`/`my_index` on peers; `{envelope, status}` outbox entries);
old files still load; redeliver replays all statuses. `advice recover`
deliberately skips envelope-signature checks (peers file died with the
device; re-pairing restores checkability).

## Batched re-delivery

Re-delivery ships advices as `advice_batch` messages (40 envelopes per
message) instead of one message each: every SimpleX message costs a full
client/relay round-trip (~0.2-0.3s on the reference Haskell stack — CLI
double-ratchet + SQLite fsync on both ends plus the relay's store-log and
SMP ack), so batching makes recovery messaging ~3 round-trips regardless
of payment count. `advice recover` accepts both the batch and the legacy
per-message form; entries are validated individually, as strictly as live
advice.

## advice command family (branch axion-advice)

Added `zcash-devtool advice {pair,send,receive}` implementing Step 1 of the
out-of-band payment spec: after a sender mines a shielded tx, it pushes an
advice envelope `{v, type, txid, height, pool, output_index}` to the recipient
over a SimpleX channel (headless simplex-chat WebSocket JSON API, client in
`src/simplex.rs`); the recipient fetches that single tx from lightwalletd and
runs one targeted `decrypt_and_store_transaction` instead of scanning.

Notes for future work:
- `fetch_transaction`/`parse_raw_transaction` were hoisted from
  `wallet/enhance.rs` into `src/helpers/tx_fetch.rs`; reuse them for any
  single-tx fetch.
- Txids on the CLI/envelope are display-order hex (byte-reversed vs
  `TxId::from_bytes`); use `commands::advice::parse_txid`.
- `tokio-tungstenite` is pinned to 0.27: 0.28+ needs stable `digest 0.11`,
  which conflicts with the `digest 0.11.0-pre` pulled in by the pinned
  `bip32 =0.6.0-pre.1`.
- simplex-chat JSON shapes vary across versions; the client skips unknown
  events at debug level and recursively searches for invitation links and
  display names instead of hardcoding paths.

## advice recovery protocol (spec 1.3.7)

Added `advice {redeliver,recover}` plus identity tokens: a wallet derives a
long-term Ed25519 identity from its BIP-39 seed (BLAKE2b-256, personals
`Zcash_AxionRoot`/`Zcash_AxionSubk`, subkey index j; all signatures
domain-separated). `advice pair --mode invite --identity <age>` sends a signed
token; the joining side stores it in `axion-peers.json`. `advice send` now
appends each envelope to `axion-outbox.json`. After seed-only restore,
`advice recover` publishes a fresh invitation, answers the sender's
challenge with a signature, and verifies every re-delivered advice with
targeted decryption (no scan); `advice redeliver` matches the proof pubkey
against stored peers (by key value, never display name) and replays the
outbox.

Behavior changes:
- `advice pair` now takes the `-w` wallet dir (needed to store tokens);
  `advice send`, `redeliver`, and `recover` require `-w` explicitly - the
  axion state files have no default-directory fallback.
- Receive-side envelope verification was extracted to
  `src/commands/advice/verify.rs` (`verify_advice`), shared by `receive`
  and `recover`; outer error = transport failure, inner Err = protocol
  rejection.
