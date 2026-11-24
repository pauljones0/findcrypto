# Blessed container image

Beginning with the first `findcrypto` tag, a maintainer-run GoReleaser process
publishes `ghcr.io/pauljones0/findcrypto`. Pull a versioned, digest-pinned image
and mount evidence read-only:

    docker pull ghcr.io/pauljones0/findcrypto:X.Y.Z
    docker pull ghcr.io/pauljones0/findcrypto@sha256:<digest>
    docker run --rm -v ./evidence:/evidence:ro \
      ghcr.io/pauljones0/findcrypto@sha256:<digest> /evidence/disk.img

Tags are the version without the `v` prefix and `latest`; pin the digest for
casework because `latest` moves. The pre-rename `v0.2.0` image remains under the
historical `ghcr.io/pauljones0/findbtc` package.

## Image facts

- Base: `scratch`; it has no shell or package manager.
- Platforms: `linux/amd64` and `linux/arm64` in one manifest.
- Commands: `/usr/bin/findcrypto` plus `/usr/bin/findbtc` compatibility.
- Entrypoint: `findcrypto`.
- User: `65534:65534` (non-root).
- Documentation: `LICENSE`, `README.md`, and `CHANGELOG.md` under
  `/usr/share/doc/findcrypto`.

Raw-device scans need the device nodes and root inside the container:

    docker run --rm --privileged --user 0 \
      -v /dev:/dev:ro ghcr.io/pauljones0/findcrypto:X.Y.Z /dev/sda

Prefer carving and case logs onto a separate writable mount, never onto the
evidence mount.

## Provenance

GoReleaser builds the static binaries once and copies those exact files into
both archives/packages and the scratch image; the Dockerfile never recompiles.
Verify the release archives and checksums as described in
[RELEASE.md](RELEASE.md), reproduce high-assurance builds independently, then
bind deployments to the registry digest.

This keeps the original Goal 21 design: one multi-architecture GoReleaser
configuration, no emulation, no second build path, and no Helm chart for a
local forensic CLI.
