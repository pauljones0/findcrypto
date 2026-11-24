# Chain support and expansion plan

FindCrypto separates three different claims that are easy to blur together:

1. **Discovery** — recognize wallet material in bytes.
2. **Recovery** — validate, complete, salvage, or unlock that material.
3. **Identity/activity** — derive public addresses and determine whether a
   candidate was actually used.

Finding a BIP39 phrase is chain-neutral; it does not by itself prove which
wallet, derivation path, passphrase, or network used it.

## Current support

| Ecosystem | Discovery | Recovery and public identity | Activity |
|---|---|---|---|
| Bitcoin | Core BDB/SQLite traces, WIF/xkeys, descriptors, Electrum, BIP39, lnd markers, deleted filesystem content | BIP39 repair, BIP44/49/84 account xpubs, address gap derivation, database salvage, Core password hashes | Optional Esplora history/funded/spent/balance lookup |
| Ethereum and EVM-compatible networks | Web3 keystores, presale shapes, generic browser-passworder vault envelopes, BIP39 | Web3 keystore password hashes; recovered BIP39 candidates derive EIP-55 addresses at `m/44'/60'/0'/0/i` | No EVM RPC/indexer lookup yet |
| BLS12-381 / ERC-2335 | Chain-neutral modular keystore JSON, commonly used by validators | Strict validation and carving; no unsupported cracker export | None |
| Solana | Cryptographically validated CLI `seed || public-key` arrays, BIP39 | Recovered BIP39 candidates derive base58 addresses with SLIP-0010 at `m/44'/501'/i'/0'` | No Solana RPC lookup yet |
| Litecoin | Chain-neutral BIP39 evidence | Base58Check P2PKH at `m/44'/2'/0'/0/i` | No chain lookup yet |
| Dogecoin | Chain-neutral BIP39 evidence | Base58Check P2PKH at `m/44'/3'/0'/0/i` | No chain lookup yet |
| Cosmos Hub | Chain-neutral BIP39 evidence | `cosmos` Bech32 accounts at `m/44'/118'/0'/0/i` | No Cosmos RPC lookup yet |
| Exodus | Strict Exodus-attributed SECO v0 prefix (not generic `SECO` alone) | Complete containers are SHA-256 checked before Hashcat mode 28200 export | No portfolio/chain inference from the container |
| Other BIP39 wallets | English BIP39 exact/near/unordered phrase evidence | Checksum repair is chain-neutral; no unlisted path is implied | None |
| SLIP39 wallets | Validated share detection | Shares are reported for a compatible wallet/tool; reconstruction is not performed | None |

The EVM address profile applies to Ethereum, Base, Arbitrum, Optimism,
Polygon, BNB Smart Chain, Avalanche C-Chain, and other networks using the same
secp256k1/Keccak account scheme. The same address may have unrelated activity
on several networks, so FindCrypto labels it `evm` rather than guessing one.

## Offline candidate confirmation

`-report -complete --reveal -known-addresses public.txt` compares completed
candidates with public identities you already control. It makes no network
calls and prints a candidate phrase only after at least one selected
profile/index matches. EVM inputs may be all-lower/all-upper; genuinely
mixed-case inputs must pass EIP-55. Bech32 checksums, Base58Check checksums, and
32-byte Solana-style Base58 shapes are also validated before search begins.

Named profiles are deterministic presets, not arbitrary path strings:

| Profile | Bounded slot |
|---|---|
| `bitcoin-standard` | BIP44/49/84, external and change, `i` in each path |
| `evm-standard` | `m/44'/60'/0'/0/i` |
| `solana-standard` | `m/44'/501'/i'/0'` |
| `litecoin-bip44` | `m/44'/2'/0'/0/i` |
| `dogecoin-bip44` | `m/44'/3'/0'/0/i` |
| `cosmos-hub` | `m/44'/118'/0'/0/i` with HRP `cosmos` |

All profiles are selected by default. Use `-recovery-profiles` to narrow them,
`-recovery-start` for the first slot, and `-recovery-count` for the number of
slots. Count is 1–100, every range must end below index 10,000, and a separate
candidate/profile work budget prevents accidental explosion.

For a non-empty BIP39 passphrase on Unix, use `-bip39-passphrase-file FILE`.
The file must be a non-symlink regular file with owner-only permissions (`0600`
or stricter), at most 4 KiB, and exactly one non-empty valid UTF-8 line without
a BOM. The value is copied, Unicode NFKD-normalized as BIP39 requires, wiped
where Go permits, and never printed, logged, or written to output. It is
intentionally not accepted on the command line or through an environment
variable. Omit the flag for the standard empty passphrase. Windows refuses this
input until an owner-only DACL can be verified robustly.

On Unix, `-complete-out identities.txt` atomically writes an owner-only handoff
with three Bitcoin account keys plus comment-only public addresses for the
selected profiles. In known-address mode, only positively matched candidate
blocks are written. `-watch` consumes the Bitcoin keys and ignores the comments.
On Windows, output inherits the destination directory's ACL and publication is
not guaranteed atomic; use a private directory and treat the handoff as
sensitive public identity data.

A no-match is not negative proof. It only says that no shown completion matched
the selected passphrase, named profiles, and bounded slots. Check truncation,
passphrase assumptions, later indexes, and wallet-specific paths before ruling
anything out; a positive transaction-history match remains much stronger than
a current-balance check.

## Highest-value next work

1. **Structured candidate manifests.** Replace comment lines with an atomic
   `0600` JSONL/CSV manifest containing candidate ID, chain, path, index, and
   public address—never phrase/private material.
2. **Wallet-specific path presets.** Add published, independently vector-tested
   legacy Ledger/Solana and wallet-family profiles without opening arbitrary
   path execution.
3. **Wallet-specific artifacts.** Build a WebExtension/LevelDB storage layer,
   then add the version-scoped Phantom, Solflare, and Keplr adapters recorded in
   [WALLET_ARTIFACTS.md](WALLET_ARTIFACTS.md). Namespace context must exclude
   installed source bundles; the shared browser-passworder envelope stays
   implementation-neutral.
4. **Activity adapters.** Add opt-in EVM, Solana, Litecoin, Dogecoin, and Cosmos
   lookups against owner-selected nodes, preserving lifetime-use evidence rather
   than balance-only filtering.
5. **Multilingual BIP39.** Add the official wordlists with Unicode-aware token
   handling and independent vectors, especially Japanese spacing/NFKD.
6. **More Cosmos SDK networks.** Add explicit coin-type/HRP presets rather than
   treating every Cosmos-family chain as Cosmos Hub.
7. **Harden private derivation.** Replace the small variable-time affine
   secp256k1 implementation with a reviewed constant-time primitive before
   claiming resistance to a co-resident timing observer. Current recovery
   derivation is intended for a trusted offline machine.

Cardano, Polkadot, Monero, and similar ecosystems are deliberately later work:
Cardano uses Icarus/BIP32-Ed25519 and CIP-1852 rather than SLIP-0010; Polkadot
commonly needs sr25519/SS58; Monero uses a different mnemonic and key/address
model. They need reviewed implementations and published vectors, not renamed
EVM or Solana code.

Relevant standards and primary references:

- [SLIP-0044 registered coin types](https://github.com/satoshilabs/slips/blob/master/slip-0044.md)
- [BIP39 mnemonic/passphrase normalization](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [Solana mnemonic restoration](https://solana.com/developers/cookbook/wallets/restore-from-mnemonic)
- [Cardano CIP-1852](https://cips.cardano.org/cip/CIP-1852)
- [Ethereum ERC-2335 keystores](https://eips.ethereum.org/EIPS/eip-2335)
- [Exodus secure-container format](https://github.com/ExodusMovement/secure-container#file-format-description)
- [Hashcat Exodus extractor](https://github.com/hashcat/hashcat/blob/master/tools/exodus2hashcat.py)
