# Migrating from findbtc to findcrypto

The project has outgrown its Bitcoin-only name: it already recognizes Ethereum,
Electrum, SLIP39, Lightning, browser-passworder, descriptor, generic secret, and now Solana
artifacts. The repository and primary command are therefore `findcrypto`.

## What changes

- Repository: `github.com/pauljones0/findbtc_sandbox` becomes
  `github.com/pauljones0/findcrypto`. GitHub redirects old clone and web URLs.
- Go module: import `github.com/pauljones0/findcrypto/detector`.
- Command: use `findcrypto` in new scripts and documentation.
- Artifacts and container: use `findcrypto_*` and
  `ghcr.io/pauljones0/findcrypto` beginning with the first findcrypto release.
- Script override: use `FINDCRYPTO=/path/to/findcrypto`.

## What keeps working

- Releases also build `findbtc` and publish `findbtc_*` compatibility archives
  and packages for one migration cycle.
- The `findcrypto` deb/rpm provides and replaces the old `findbtc` package while
  installing both command names; the two package names intentionally conflict
  so package managers never leave two owners for `/usr/bin/findbtc`.
- The existing `pauljones0/homebrew-findbtc` tap,
  `pauljones0/scoop-findbtc` bucket, `pauljones0.findbtc` Winget identifier, and
  `FINDBTC` script override continue to work. They install the compatibility
  command and are deliberately not presented as new generic package channels.
- JSON hits keep the frozen hits-v1 schema contract. DFXML keeps its historical
  `jakewins/findbtc` namespace. Changing either would break evidence consumers
  for no recovery benefit.
- Existing checkpoints and case logs remain readable; branding is metadata, not
  a resume identity input.

## Source users

Update imports and install the primary command:

```sh
go install github.com/pauljones0/findcrypto@main
findcrypto -version
```

Use `@main` until the first findcrypto tag is published; after that, `@latest`
is the stable install path.
