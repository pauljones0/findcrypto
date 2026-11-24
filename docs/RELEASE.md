# Releases: local verification and manual publication

This repository intentionally ships no GitHub Actions. Tags do not publish
anything by themselves. A maintainer runs the checks and GoReleaser locally,
reviews the resulting artifacts, and explicitly publishes them. Releases carry
checksums and SPDX SBOMs, but no GitHub OIDC/SLSA provenance attestation.

## Rename transition

The first tag after the repository rename establishes `findcrypto` as the
primary release line while retaining `findbtc` for one compatibility cycle:

- `findcrypto_<version>_<os>_<arch>` is the primary archive;
- `findbtc_<version>_<os>_<arch>` is the compatibility archive;
- the `findcrypto` deb/rpm installs both commands and replaces/conflicts with
  the old package;
- a compatibility `findbtc` deb/rpm preserves the old package name; and
- `ghcr.io/pauljones0/findcrypto` contains both commands and starts
  `findcrypto`.

Tags through `v0.2.0` predate the rename and contain only `findbtc` artifacts.
The historical Homebrew, Scoop, and Winget channels remain frozen at v0.2;
there is no generic channel until one is actually created.

## Maintainer checklist

Use the versions in `scripts/tool-versions.env`. The Linux-only full check
additionally needs John jumbo, hashcat, the pinned BTCRecover checkout
(`BTCR_DIR`), Staticcheck, Docker/Buildx, GoReleaser, Berkeley DB utilities,
xfsprogs, Sleuth Kit, `dpkg-deb`, zsh, fish, and man-db:

    scripts/check.sh core
    scripts/check.sh floor
    mise exec -- env BTCR_DIR=/path/to/btcrecover scripts/check.sh full
    git status --short

`full` refuses missing oracle tools and mismatched pins before expensive work.
It then runs formatting, build, vet, the complete Go suite, vulnerability and
static analysis, five fuzz targets, owner/password rehearsals, package-pin
checks, and a GoReleaser archive/package/container snapshot. The final snapshot
verifier checks every OS/architecture artifact, all checksums, package metadata
and payloads, completion syntax, container architecture/user/entrypoint, and
both command names. Inspect `dist/` and install at least one generated package
before continuing.

Create and push the version tag only from that clean, reviewed commit. To
publish, install Syft, authenticate Docker to `ghcr.io`, provide a GitHub token
allowed to create the release/package, and run:

    export GITHUB_TOKEN=...
    mise exec -- goreleaser release --clean

The full check refuses a Go version other than the pinned release version.
This is an external publication step: review the tag and `dist/checksums.txt`
before running it. GoReleaser uploads the GitHub release and versioned container
images according to `.goreleaser.yaml`; no workflow will repair or retry a
partial publication.

## What a release contains

Platform archives (`.tar.gz`, or `.zip` on Windows) contain one command plus
`LICENSE`, `README.md`, and `CHANGELOG.md`. Linux releases also include deb/rpm
packages. The release carries:

- `checksums.txt` — SHA-256 for archives, packages, and SBOMs; and
- `<archive>.sbom.json` — an SPDX software bill of materials.

## Verifying a download

Fetch the archive, `checksums.txt`, and its SBOM from the same tag. The checksum
file lists every release artifact, so select the two files you downloaded
before checking it (replace `X.Y.Z` with the release version):

    archive=findcrypto_X.Y.Z_linux_amd64.tar.gz
    sbom="$archive.sbom.json"
    awk -v a="$archive" -v s="$sbom" '$2 == a || $2 == s' checksums.txt > selected-checksums.txt
    test "$(wc -l < selected-checksums.txt)" -eq 2
    sha256sum -c selected-checksums.txt
    python3 -c "import json,sys; [print(p['name'], p.get('versionInfo')) for p in json.load(open(sys.argv[1]))['packages']]" "$sbom"

A checksum proves that the download matches the maintainer-published artifact;
it does not prove who built it. For high-assurance forensic use, reproduce the
binary from the tag on an isolated machine and compare behavior and build
metadata.

## Reproducing a build

Tagged builds stamp `main.version`, set source modification time from the
commit, disable cgo, and compile with `-trimpath`:

    git checkout vX.Y.Z
    CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=X.Y.Z" -o findcrypto-repro .
    ./findcrypto-repro -version

Run `scripts/check.sh core` in that checkout. Exact stripped Go binaries may
still reflect toolchain differences, so use the version pinned in
`scripts/tool-versions.env` when comparing bytes.

## Redistribution

findcrypto is GPL-3.0-or-later. Keep `LICENSE`, the matching SBOM, and
`checksums.txt` with redistributed binaries. Snapshot artifacts are development
outputs, never releases.
