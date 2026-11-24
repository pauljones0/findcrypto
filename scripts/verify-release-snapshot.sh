#!/usr/bin/env bash
# Verify the package/container behavior that used to live in hosted workflow
# steps. Run after a clean GoReleaser snapshot; this script never installs a
# package or modifies the host outside a temporary directory.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
REPO=$(cd "$SCRIPT_DIR/.." && pwd -P)
DIST=${1:-$REPO/dist}

if [ "$(uname -s)" != Linux ]; then
	echo "snapshot verification requires Linux" >&2
	exit 1
fi
for tool in docker dpkg-deb zsh fish man sha256sum; do
	command -v "$tool" >/dev/null 2>&1 || {
		echo "snapshot verification needs $tool on PATH" >&2
		exit 1
	}
done
test -d "$DIST" || { echo "snapshot directory not found: $DIST" >&2; exit 1; }

one_artifact() {
	pattern=$1
	set -- "$DIST"/$pattern
	if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
		echo "expected exactly one snapshot artifact matching $pattern" >&2
		exit 1
	fi
	printf '%s\n' "$1"
}

for name in findcrypto findbtc; do
	for os in darwin linux windows; do
		for arch in amd64 arm64; do
			ext=tar.gz
			[ "$os" = windows ] && ext=zip
			one_artifact "${name}_*_${os}_${arch}.${ext}" >/dev/null
		done
	done
done
for name in findcrypto findbtc; do
	for arch in amd64 arm64; do
		one_artifact "${name}_*_linux_${arch}.deb" >/dev/null
		one_artifact "${name}_*_linux_${arch}.rpm" >/dev/null
	done
done

(cd "$DIST" && sha256sum -c checksums.txt)

amd64_image=ghcr.io/pauljones0/findcrypto:latest-amd64
arm64_image=ghcr.io/pauljones0/findcrypto:latest-arm64
image_config=$(docker image inspect "$amd64_image" --format '{{.Architecture}} {{.Config.User}} {{join .Config.Entrypoint " "}}')
test "$image_config" = "amd64 65534:65534 /usr/bin/findcrypto"
test "$(docker image inspect "$arm64_image" --format '{{.Architecture}}')" = arm64
docker run --rm "$amd64_image" -version | grep -Eq '^findcrypto '
docker run --rm --entrypoint /usr/bin/findbtc "$amd64_image" -version | grep -Eq '^findbtc '

primary_deb=$(one_artifact 'findcrypto_*_linux_amd64.deb')
compat_deb=$(one_artifact 'findbtc_*_linux_amd64.deb')
for field in Provides Conflicts Replaces; do
	dpkg-deb -f "$primary_deb" "$field" | grep -Eq '(^|[,[:space:]])findbtc([,[:space:]]|$)'
done
test "$(dpkg-deb -f "$compat_deb" Package)" = findbtc

pkgroot=$(mktemp -d)
trap 'rm -rf -- "$pkgroot"' EXIT
dpkg-deb -x "$primary_deb" "$pkgroot"
for path in \
	usr/bin/findcrypto \
	usr/bin/findbtc \
	usr/share/man/man1/findcrypto.1 \
	usr/share/bash-completion/completions/findcrypto \
	usr/share/zsh/vendor-completions/_findcrypto \
	usr/share/zsh/site-functions/_findcrypto \
	usr/share/fish/vendor_completions.d/findcrypto.fish \
	usr/share/doc/findcrypto/BENCHMARKS.md \
	usr/share/doc/findcrypto/PIPELINE_INGEST.md \
	usr/share/doc/findcrypto/RESOURCE_BOUNDS.md; do
	test -e "$pkgroot/$path" || { echo "snapshot package lacks /$path" >&2; exit 1; }
done
"$pkgroot/usr/bin/findcrypto" -version | grep -Eq '^findcrypto '
"$pkgroot/usr/bin/findbtc" -version | grep -Eq '^findbtc '
bash -n "$pkgroot/usr/share/bash-completion/completions/findcrypto"
zsh -n "$pkgroot/usr/share/zsh/vendor-completions/_findcrypto"
fish --no-execute "$pkgroot/usr/share/fish/vendor_completions.d/findcrypto.fish"
MANPAGER=cat PAGER=cat man -l "$pkgroot/usr/share/man/man1/findcrypto.1" | grep -q 'SEE ALSO'

echo "snapshot packages and containers verified"
