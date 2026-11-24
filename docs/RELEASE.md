# Releases: verification, compatibility, and redistribution

Every tagged release (`v*`) is built by GitHub Actions through GoReleaser and
ships checksums, per-archive SPDX SBOMs, and GitHub build-provenance
attestations. Verify a download before trusting it with evidence.

## Rename transition

The first tag after the repository rename establishes `findcrypto` as the
primary release line. The workflow also builds the same commit as `findbtc` for
one compatibility cycle. This is intentional migration support, not a second
codebase:

- `findcrypto_<version>_<os>_<arch>` is the primary archive;
- `findbtc_<version>_<os>_<arch>` is the compatibility archive;
- the `findcrypto` deb/rpm contains both `/usr/bin/findcrypto` and
  `/usr/bin/findbtc`, and replaces/conflicts with the old `findbtc` package;
- a compatibility `findbtc` deb/rpm preserves the old package name; and
- `ghcr.io/pauljones0/findcrypto` contains both commands and starts
  `findcrypto`.

Tags through `v0.2.0` predate the rename and contain only `findbtc` artifacts.
Do not guess that a generic package-manager channel exists: the README names
only install paths that are real and tested.

## What a release contains

Platform archives (`.tar.gz`, or `.zip` on Windows) contain one command plus
`LICENSE`, `README.md`, and `CHANGELOG.md`. Linux users should prefer the managed
packages. The release also carries:

- `checksums.txt` — SHA-256 of every archive, package, and SBOM;
- `<archive>.sbom.json` — the SPDX software bill of materials; and
- a provenance attestation bound to the repository, workflow, commit, and
  checksums file through GitHub OIDC.

## Verifying a download

1. Fetch the archive, `checksums.txt`, and its `.sbom.json` from the same tag.
2. Check integrity:

       sha256sum -c checksums.txt

3. Check provenance with the GitHub CLI:

       gh attestation verify findcrypto_*_linux_amd64.tar.gz \
         -R pauljones0/findcrypto

4. Optionally inspect the SBOM:

       python3 -c "import json,sys; \
         [print(p['name'], p.get('versionInfo')) \
          for p in json.load(open(sys.argv[1]))['packages']]" \
         findcrypto_*_linux_amd64.tar.gz.sbom.json

Expect `github.com/pauljones0/findcrypto` and the Go toolchain. The module has
no third-party runtime dependencies, and no dependency is fetched at runtime.

## Reproducing a build

Tagged builds stamp `main.version`, set the source modification time from the
commit, disable cgo, and compile with `-trimpath`:

    git checkout vX.Y.Z
    CGO_ENABLED=0 go build -trimpath -ldflags \
      "-s -w -X main.version=X.Y.Z" -o findcrypto-repro .
    ./findcrypto-repro -version

The release pipeline, Go version, and provenance remain the authoritative build
record. Compare behavior, version, and SBOM as well as the checksum.

## Redistribution

findcrypto is GPL-3.0-or-later. Keep `LICENSE`, the matching SBOM, and
`checksums.txt` with any redistributed binary so the recipient can repeat the
checks. Snapshot builds (`*-SNAPSHOT-*`) are CI/dev artifacts, never releases.

## Package-manager migration (maintainers)

The existing channels are compatibility channels and keep their real names:

- Homebrew: [`pauljones0/homebrew-findbtc`](https://github.com/pauljones0/homebrew-findbtc),
  cask `findbtc`;
- Scoop: [`pauljones0/scoop-findbtc`](https://github.com/pauljones0/scoop-findbtc),
  manifest `findbtc`; and
- Winget: identifier `pauljones0.findbtc`, with bootstrap manifests under
  `packaging/winget`.

Their immutable v0.2 pins and offline verifier fixtures remain unchanged. CI
still installs all three legacy paths and separately snapshot-builds the new
generic artifacts. GoReleaser renders updated compatibility Homebrew/Winget
metadata from the `findbtc` archive; cross-repository upload and Winget
submission remain manual, separately authorized actions.

Create generic Homebrew/Scoop/Winget channels only when they actually exist,
then update this file and the native-OS install smoke in the same commit. Until
then, source install and release downloads are the honest generic paths.
