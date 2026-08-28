# zcash-devtool — `axion-advice` fork

> ⚠️ **This is a fork.** Branch [`axion-advice`](https://github.com/nikkolasg/zcash-devtool/tree/axion-advice)
> adds the **out-of-band payment advice** command family (`zcash-devtool advice …`)
> for the [Axion Step 1 demo](https://github.com/nikkolasg/axion) — an
> experimental research prototype, regtest only. Everything below this section
> is the unmodified upstream README.

## 📖 The changes, as a story

The branch is written to be read **commit by commit, oldest first** — each
commit is one self-contained chapter that compiles and passes its tests.
[Browse the commits](https://github.com/nikkolasg/zcash-devtool/commits/axion-advice)
or see the [whole diff vs upstream](https://github.com/nikkolasg/zcash-devtool/compare/c8322f7...axion-advice).

1. [`c567b0a`](https://github.com/nikkolasg/zcash-devtool/commit/c567b0a72d9c8080f79eda92b14aecc7396dbec2)
   **The transport.** Before anything can be advised, the wallet needs a
   private channel: a thin async WebSocket client for the simplex-chat CLI —
   corrId-matched requests, an event queue so nothing is lost, hard deadlines.
2. [`8a71aa1`](https://github.com/nikkolasg/zcash-devtool/commit/8a71aa12c562d40d761539762e581231199f62f9)
   **Borrow the wallet's own sync.** The privacy story depends on the receive
   path making *the same requests a normal sync makes*, so the sync primitives
   (subtree roots, chain tip, block download, reorg rewind) are hoisted out of
   `wallet sync` into shared helpers — behaviour unchanged, now reusable.
3. [`a38762a`](https://github.com/nikkolasg/zcash-devtool/commit/a38762aaa21e7f9420225fd9df14ca45e119d5e6)
   **The protocol core.** Seed-derived Ed25519 identity subkeys (one per
   contact, so two senders share zero identifiers), the versioned wire
   messages with domain-separated signatures, the ack replay counter, and the
   peer/outbox store. No commands yet — just the vocabulary, fully unit-tested.
4. [`0e5414b`](https://github.com/nikkolasg/zcash-devtool/commit/0e5414b737fcdc3e93877f3c923b9bd20d276e51)
   **`advice pair`.** The first wired command: establish the SimpleX channel
   and exchange signed identity tokens; the invite side mints a fresh
   diversified address for the peer to pay.
5. [`7c47eb5`](https://github.com/nikkolasg/zcash-devtool/commit/7c47eb56dcdadd0b738a0151e79ea07763d6bd09)
   **`advice send`.** After a shielded tx is mined, locate the outgoing output
   with the sender's own viewing keys, sign an advice envelope
   `{txid, height, pool, index}`, ship it, record it in the outbox, and apply
   the address ratchet when the signed ack comes back.
6. [`6a4cda7`](https://github.com/nikkolasg/zcash-devtool/commit/6a4cda7042dc934d96a8c92571cf673444c26948)
   **`advice receive` — the headline.** Verify advice *without telling the
   indexer which tx is yours*: download the same block ranges a vanilla sync
   would, trial-decrypt the advised block first (instant visibility), then
   scan the whole gap to completion — the dual rail, with the shared rewind
   handling reorgs and birthday boundaries.
7. [`190280f`](https://github.com/nikkolasg/zcash-devtool/commit/190280f147af09c574ab6f1b8224c99065138630)
   **`advice flush`.** Reliability: re-send every pending envelope on
   reconnection, surface overdue ones, collect late acks.
8. [`dc5625b`](https://github.com/nikkolasg/zcash-devtool/commit/dc5625b74da0144f9c674145e5f8880ade6339e7)
   **Recovery (`redeliver`/`recover`).** The challenge/proof handshake that
   lets a wallet prove its seed-derived identity to a contact and have the
   contact replay its outbox — history back with no rescan.
9. [`d417a4b`](https://github.com/nikkolasg/zcash-devtool/commit/d417a4b8aaa90e80aa8cfa73746bb933b80226c6)
   **The changelog** tracking how the family evolved.
10. [`e1f7c01`](https://github.com/nikkolasg/zcash-devtool/commit/e1f7c0128d91341aa6a6a0577f7d619892eb690e)
    **…and the honest ending: recovery disabled.** With per-contact indices, a
    seed-only restore cannot know which index each contact holds — that map is
    the future Step-3 encrypted backup's job. Rather than ship a command that
    silently needs state a real user would have lost, chapter 8 is compiled
    out behind the `unstable-recovery` feature (code and tests kept) until the
    backup exists. Funds never depend on it: chain scanning finds everything.

Protocol details (wire formats, signing inputs, anonymity analysis) live in the
demo repo's [TECHNICAL.md](https://github.com/nikkolasg/axion/blob/main/TECHNICAL.md).

---

# zcash-devtool (upstream README)

This repository contains a CLI app for working with Zcash transactions and the
Zcash blockchain, including stateless Zcash wallet functionality based upon the
`zcash_client_backend` and `zcash_client_sqlite` crates. It is built by
developers, for developers for use in prototyping Zcash functionality, and
should not be considered production-ready. The command-line API that this tool
exposes can and will change at any time and without warning.

## Security Warnings

**DO NOT USE THIS IN PRODUCTION!!!**

This app has not been written with security in mind. It does however have affordances
such as encryption of the mnemonic seed phrases that should make it viable for small
scale experimentation, at your own risk.

## Usage

No binary artifacts are provided for this crate; it is generally used via
`cargo run` as follows:

To obtain the help docs:
```
cargo run --release -- --help
```
To obtain the help for a specific command (in this case, `init`)
```
cargo run --release -- --help init
```

To create a new empty testnet wallet:
```
cargo run --release -- wallet -w <wallet_dir> init --name "<account_name>" -i <identity_file> -n test
cargo run --release -- wallet -w <wallet_dir> sync
```

Note: The `-i` (identity) parameter specifies an age identity file for encrypting the mnemonic phrase. The file will be generated if it doesn't exist.

See the help docs for `init` for additional information, including for how to
initialize a mainnet wallet. Initializing a mainnet wallet will require
specifying a mainnet lightwallet server, e.g.
```
cargo run --release -- wallet -w <wallet_dir> init --name "<account_name>" -i <identity_file> -n main -s zecrocks
cargo run --release -- wallet -w <wallet_dir> sync -s zecrocks
```

To restore an existing wallet from a mnemonic seed phrase, use `restore-mnemonic`:
```
cargo run --release -- wallet -w <wallet_dir> restore-mnemonic --name "<account_name>" -i <identity_file> -n test
cargo run --release -- wallet -w <wallet_dir> sync
```
You will be prompted to enter the mnemonic phrase to restore. As with `init`,
the `-i` (identity) parameter specifies an age identity file used to encrypt the
mnemonic phrase, and the file will be generated if it doesn't exist. Unless you
pass `--birthday`, the wallet's birthday defaults to the network's Sapling
activation height so that the entire history in which it could have received
funds is scanned.

Whenever you update the `zcash_client_sqlite` dependency, in order to run
necessary migrations:
```
cargo run --release -- wallet -w <wallet_dir> upgrade
```

If you want to run with debug or trace logging:
```
RUST_LOG=debug cargo run --release -- wallet -w <wallet_dir> <command>
```
### Video tutorial of Zcash Devtool
Kris Nuttycombe (@nuttycom) presented this tool during ZconVI. The session is available
on Youtube [here](https://www.youtube.com/watch?v=5gvQF5oFT8E)

[![Youtube preview of the ZconVI presentation Zcash-devtool: the Zcash development multitool](https://img.youtube.com/vi/5gvQF5oFT8E/0.jpg)](https://www.youtube.com/watch?v=5gvQF5oFT8E)

The code developed in this demo resulted in [this](https://github.com/zcash/zcash-devtool/pull/86) pull request.

## Documentation

For a step-by-step guide for how to get started using these tools, see [this
walkthrough](doc/walkthrough.md).

## License

All code in this workspace is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
