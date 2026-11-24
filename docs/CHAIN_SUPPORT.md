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
| Ethereum and EVM-compatible networks | Web3 keystores, presale shapes, browser-passworder/MetaMask-style vaults, BIP39 | Keystore password hashes; recovered BIP39 candidates derive EIP-55 addresses at `m/44'/60'/0'/0/i` | No EVM RPC/indexer lookup yet |
| Solana | Cryptographically validated CLI `seed || public-key` arrays, BIP39 | Recovered BIP39 candidates derive base58 addresses with SLIP-0010 at `m/44'/501'/i'/0'` | No Solana RPC lookup yet |
| Other BIP39 wallets | English BIP39 exact/near/unordered phrase evidence | Checksum repair is chain-neutral, but no chain-specific address adapter yet | None |
| SLIP39 wallets | Validated share detection | Shares are reported for a compatible wallet/tool; reconstruction is not performed | None |

The EVM address profile applies to Ethereum, Base, Arbitrum, Optimism,
Polygon, BNB Smart Chain, Avalanche C-Chain, and other networks using the same
secp256k1/Keccak account scheme. The same address may have unrelated activity
on several networks, so FindCrypto labels it `evm` rather than guessing one.

`-report -complete --reveal -complete-out keys.txt` writes three Bitcoin
watch-only account keys per candidate plus comment-only EVM and Solana public
addresses. It never writes the mnemonic or a private key. `-watch` consumes the
Bitcoin keys; compare the public EVM/Solana lines with old exchange statements,
tax records, wallet screenshots, or a trusted local node. This derivation
currently assumes an empty BIP39 passphrase; a non-empty passphrase changes all
of these identities and must not be ruled out by an empty result. The CLI emits
only EVM index 0 and Solana account 0 today; a non-match also does not exclude
later indexes, legacy Ledger/Solana schemes, or another wallet-specific path.

## Highest-value next work

1. **Known-address matching.** Accept a file of public addresses and compare it
   offline against bounded candidate paths. This is the safest version of the
   original `wheres-my-wallet` idea: no phrase or address set goes to a public
   provider, and hundreds of candidates collapse to explicit matches.
2. **BIP39 passphrases.** Read passphrases from a protected file or hidden
   prompt, apply mandatory Unicode NFKD normalization, and match only against
   known public identities. Never accept a passphrase on the command line or in
   an environment variable.
3. **Structured candidate manifests.** Replace comment lines with an atomic
   `0600` JSONL/CSV manifest containing candidate ID, chain, path, index, and
   public address—never phrase/private material.
4. **Multilingual BIP39.** Add the official wordlists with Unicode-aware token
   handling and independent vectors, especially Japanese spacing/NFKD.
5. **More BIP44 adapters.** Litecoin and Dogecoin are low-risk next additions;
   Cosmos SDK chains follow with explicit coin type and Bech32 HRP profiles.
6. **Wallet artifacts.** Add ERC-2335 validator keystores and evidence-backed
   Phantom, Solflare, Keplr, and Exodus formats. A generic
   `browser-passworder` envelope should not be attributed to MetaMask without
   application evidence.
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
- [Solana mnemonic restoration](https://solana.com/developers/cookbook/wallets/restore-from-mnemonic)
- [Cardano CIP-1852](https://cips.cardano.org/cip/CIP-1852)
- [Ethereum ERC-2335 keystores](https://eips.ethereum.org/EIPS/eip-2335)
