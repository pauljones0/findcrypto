# Changelog

## Unreleased — findcrypto

This is the first release under the `findcrypto` name. It also collects the
large body of recovery work completed after `v0.2.0`; the repository had 74
unreleased commits when the rename began.

### Added

- Multichain identity: the module, primary command, release artifacts,
  container, help text, and documentation now use `findcrypto`.
- A validated Solana CLI keypair detector. It accepts only 64-byte Ed25519
  keypairs whose public half is derived from the embedded seed, avoiding noisy
  matches on arbitrary JSON byte arrays.
- Esplora address activity lookup for watch-only triage. Exports now distinguish
  an unused address from a previously used address with a zero current balance
  by including transaction, funded, spent, balance, and `used` fields.
- Checksum-gated repair of one wrong-but-valid BIP39 word, in addition to the
  existing one- or two-gap completion flow.
- A clean-room integration record for the useful `wheres-my-wallet` recovery
  ideas, with its secret-printing/network/checkpoint hazards explicitly rejected.
- Offline public identity derivation for recovered BIP39 candidates: EIP-55 EVM
  addresses at `m/44'/60'/0'/0/i` and Solana SLIP-0010 addresses at
  `m/44'/501'/i'/0'`, independently cross-checked and emitted without private
  material. One EVM profile covers Ethereum and compatible networks.
- Offline known-address matching across bounded, named recovery profiles.
  Bitcoin BIP44/49/84 external/change, EVM, Solana, Litecoin BIP44, Dogecoin
  BIP44, and Cosmos Hub identities can be searched without a network call;
  unmatched candidate phrases remain hidden.
- Protected BIP39 passphrase input with mandatory Unicode NFKD normalization,
  strict owner-only Unix file handling, fail-closed Windows behavior until DACL
  validation exists, and no argv/environment-value surface.
- Strict ERC-2335 BLS12-381 keystore detection and Exodus-attributed SECO v0
  detection. Complete Exodus containers export checksum-verified Hashcat mode
  28200 material.
- Guided target advice, multi-target scans and reports, stdin/patch scanning,
  verified password-recovery handoffs, baseline suppression, secure secret
  profiles, generated completions/man pages, and owner recovery rehearsals.
- Filesystem recovery for FAT/exFAT and XFS, partition-aware multi-volume
  checkpoints, deleted FAT long filenames, and content-bound crash resume.
- Congestion-safe nested archive resume with no-drop publication and adversarial
  acceptance coverage.

### Changed

- The Go module path is `github.com/pauljones0/findcrypto`.
- The supported Go floor is 1.26 (current old-stable); release builds pin Go
  1.27.4 rather than following a mutable toolchain label.
- `findcrypto` is the primary executable. Releases continue to publish a
  `findbtc` compatibility executable and compatibility artifacts for existing
  automation and package-manager channels.
- Release tooling uses reproducible `-trimpath` builds, current static-analysis
  tools, dual-architecture packages, SBOMs, and a scratch container. Hosted
  GitHub Actions were removed in favor of explicit local `core`/`full` checks
  and manual publication; releases no longer claim hosted provenance.
- Recovery guidance treats any address history—not only a positive current
  balance—as evidence worth investigating.
- Watch-only activity lookups are deduplicated, cancellation-aware, and bounded
  to eight concurrent requests; invalid BIP32 children are skipped without
  silently shortening the requested address range.
- Browser-passworder envelopes now use the implementation-neutral
  `browser-passworder-vault` label. Reports continue to read the historical
  `metamask-vault` label for compatibility, but new evidence does not claim a
  wallet brand the envelope cannot prove.
- Crack guidance now splits Core, Web3 scrypt/PBKDF2, and Exodus hashes into
  separate mode-specific files, and the current local full-check target pins
  Hashcat 8.0.0.

### Security

- On Unix, sensitive recovery outputs are staged and published atomically with
  owner-only permissions. Windows inherits the destination directory ACL and
  is documented accordingly; protected passphrase input fails closed there.
- Forensic case logs are created and maintained with owner-only permissions.
- Private extended keys remain refused by watch-only mode, and network activity
  remains explicit opt-in.
- Mixed-case EVM known addresses must pass EIP-55; passphrase and known-address
  files reject symlinks, non-regular files, growth beyond their bounds, and
  identity changes during open.
- Completion output cannot alias its report, public-address, or passphrase
  input; empty/BOM passphrase files are refused, and work limits count only
  actual deduplicated candidates.

### Compatibility

- The hits-v1 schema identifier and the historical DFXML XML namespace remain
  frozen so existing consumers continue to parse old and new evidence.
- The `findbtc` Homebrew tap, Scoop bucket, Winget identifier, package names,
  and `FINDBTC` script variable remain supported as migration aliases.
- The primary deb/rpm provides and replaces the old `findbtc` package while
  installing both command names, preventing two packages from owning the same
  compatibility binary.

### Fixed

- The live XFS geometry oracle now disables the `exchange` and `parent`
  defaults introduced by xfsprogs 7.2, keeping the test focused on supported
  sector geometry rather than rejecting a newly generated incompatibility mask.
- The password-recovery harness launches the selected Python interpreter at
  its real path. A scratch-directory symlink could make CPython lose a venv's
  `pyvenv.cfg`, hide the pinned BTCRecover dependencies, and falsely report no
  recovered passwords despite a zero tool exit.

## v0.2.0

The last release under the original name. See the Git history and
[GOALS.md](GOALS.md) for the detailed implementation ledger.
