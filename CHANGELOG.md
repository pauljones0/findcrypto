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
- Release automation uses reproducible `-trimpath` builds, current supported
  GitHub Actions, current static-analysis tools, dual-architecture packages,
  SBOMs, provenance, and a scratch container.
- Recovery guidance treats any address history—not only a positive current
  balance—as evidence worth investigating.
- Watch-only activity lookups are deduplicated, cancellation-aware, and bounded
  to eight concurrent requests; invalid BIP32 children are skipped without
  silently shortening the requested address range.

### Security

- Sensitive recovery outputs are created atomically with owner-only permissions;
  existing destinations are tightened before replacement.
- Forensic case logs are created and maintained with owner-only permissions.
- Private extended keys remain refused by watch-only mode, and network activity
  remains explicit opt-in.

### Compatibility

- The hits-v1 schema identifier and the historical DFXML XML namespace remain
  frozen so existing consumers continue to parse old and new evidence.
- The `findbtc` Homebrew tap, Scoop bucket, Winget identifier, package names,
  and `FINDBTC` script variable remain supported as migration aliases.
- The primary deb/rpm provides and replaces the old `findbtc` package while
  installing both command names, preventing two packages from owning the same
  compatibility binary.

## v0.2.0

The last release under the original name. See the Git history and
[GOALS.md](GOALS.md) for the detailed implementation ledger.
