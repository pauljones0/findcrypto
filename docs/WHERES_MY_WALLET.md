# `wheres-my-wallet` integration record

The `pauljones0/wheres-my-wallet` repository is a small 2021 Node.js mnemonic
recovery prototype (a fork of `adamgall/wheres-my-wallet`). It has useful
recovery ideas, but it is not safe to merge as code: it prints candidate
mnemonics, uses a public Ethereum provider directly, evaluates an environment
variable to select a wordlist, writes a non-atomic plaintext progress file, and
depends on an obsolete JavaScript stack. No source was copied.

The useful ideas were reimplemented against findcrypto's privacy and forensic
contracts:

| Prototype idea | findcrypto integration |
|---|---|
| Replace every mnemonic position with every BIP39 word | `-report -complete` now performs deterministic, checksum-gated one-position substitution when every supplied word is valid but the phrase checksum fails. This closes the wrong-but-valid-word gap. |
| Decide candidates by a positive current balance | Watch-only Esplora results now retain transaction count, lifetime funded/spent totals, balance, and `used`. A real but fully spent wallet is not discarded. |
| Try a configurable address gap | `-watch-count` already provides bounded local derivation, defaulting to the standard 20-address gap and allowing an explicit increase. |
| Resume a large search | Existing content-bound checkpoint/resume is stronger: journals are atomic, identity-gated, and tested across crashes and nested archive congestion. Plain mnemonic progress files are not adopted. |
| Derive several chain-specific paths | Bitcoin BIP44/49/84 watch-only handoff remains implemented. Additional chain adapters should be added only with independent vectors, offline-by-default behavior, bounded paths, and demand; Solana keypair detection is the first new-chain addition in this migration. |

Two-word substitution where both damaged tokens are still valid dictionary words
is intentionally left to BTCRecover: the naive search is hundreds of millions
of combinations for a 12-word phrase. findcrypto handles two explicit unknown
gaps, while BTCRecover owns large permutation and token searches.

This is a clean-room behavior integration. The prototype has no declared license
in its repository, providing another reason not to transplant its source.
