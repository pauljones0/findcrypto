#!/usr/bin/env bash
# Local replacement for the removed hosted CI. `core` exercises the portable
# source tree, `floor` repeats it with the declared minimum Go toolchain, and
# Linux `full` adds mandatory external oracles/tools, fuzzing, and verified
# package/container snapshots.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
REPO=$(cd "$SCRIPT_DIR/.." && pwd -P)
# shellcheck source=tool-versions.env
source "$SCRIPT_DIR/tool-versions.env"

MODE=${1:-core}
REQUESTED_MODE=$MODE
case "$MODE" in
core|full) ;;
floor)
	export GOTOOLCHAIN="go$GO_FLOOR_VERSION"
	MODE=core
	;;
*) echo "usage: scripts/check.sh [core|floor|full]" >&2; exit 2 ;;
esac

need() {
	command -v "$1" >/dev/null 2>&1 || {
		echo "full check needs $1 on PATH" >&2
		exit 1
	}
}

expect_version() {
	label=$1
	got=$2
	want=$3
	if [ "$got" != "$want" ]; then
		echo "full check needs $label $want (found ${got:-unknown})" >&2
		exit 1
	fi
}

if [ "$REQUESTED_MODE" = full ]; then
	if [ "$(uname -s)" != Linux ]; then
		echo "full checks require Linux for the BDB, FAT/exFAT, XFS, package, and container oracles" >&2
		exit 1
	fi
	test "$(go env GOVERSION)" = "go$GO_RELEASE_VERSION" || {
		echo "full check needs Go $GO_RELEASE_VERSION" >&2
		exit 1
	}
	for tool in staticcheck goreleaser docker dpkg-deb zsh fish man xfs_db mkfs.xfs fls icat fsstat; do
		need "$tool"
	done
	bdb_oracle=
	for tool in db_verify db5.3_verify db5.1_verify db4.8_verify; do
		if command -v "$tool" >/dev/null 2>&1; then
			bdb_oracle=$tool
			break
		fi
	done
	if [ -z "$bdb_oracle" ]; then
		echo "full check needs db_verify (db5.3-util on Debian) on PATH" >&2
		exit 1
	fi
	: "${BTCR_DIR:?full check needs BTCR_DIR pointing at the pinned BTCRecover checkout}"
	JOHN_BIN=${JOHN:-john}
	HASHCAT_BIN=${HASHCAT:-hashcat}
	PYTHON_BIN=${PYTHON:-python3}
	for spec in "$JOHN_BIN" "$HASHCAT_BIN" "$PYTHON_BIN"; do
		case "$spec" in
		*/*) test -x "$spec" || { echo "full check cannot execute $spec" >&2; exit 1; } ;;
		*) need "$spec" ;;
		esac
	done
	staticcheck_version=$(staticcheck -version | awk 'NR == 1 { print $2; exit }')
	goreleaser_version=$(goreleaser --version | awk '$1 == "GitVersion:" { print $2; exit }')
	hashcat_version=$("$HASHCAT_BIN" --version | tr -d '\r\n')
	john_banner=$("$JOHN_BIN" 2>&1 || true)
	john_version=$(printf '%s\n' "$john_banner" | sed -n 's/^John the Ripper \([^ ]*\).*$/\1/p' | head -n 1)
	expect_version Staticcheck "$staticcheck_version" "$STATICCHECK_VERSION"
	expect_version GoReleaser "$goreleaser_version" "$GORELEASER_VERSION"
	expect_version hashcat "$hashcat_version" "v$HASHCAT_VERSION"
	expect_version John "$john_version" "$JOHN_VERSION"
	btcr_head=$(git -C "$BTCR_DIR" rev-parse HEAD)
	expect_version BTCRecover "$btcr_head" "$BTCR_SHA"
	"$PYTHON_BIN" - "$ETH_KEYFILE_VERSION" "$SETUPTOOLS_VERSION" <<'PY'
import importlib.metadata as metadata
import sys

expected = {"eth-keyfile": sys.argv[1], "setuptools": sys.argv[2]}
for package, want in expected.items():
    got = metadata.version(package)
    if got != want:
        raise SystemExit(f"full check needs {package} {want} (found {got})")
from Crypto.Cipher import AES  # noqa: F401
from Crypto.Hash import keccak  # noqa: F401
PY
	docker buildx version >/dev/null
fi

CHECK_TMP=$(mktemp -d)
trap 'rm -rf -- "$CHECK_TMP"' EXIT
cd "$REPO"

echo "==> formatting"
unformatted=$(gofmt -l .)
if [ -n "$unformatted" ]; then
	echo "$unformatted" >&2
	exit 1
fi

echo "==> build, vet, and full tests"
go build -o "$CHECK_TMP/findcrypto" .
go build ./...
go vet ./...
go test ./... -count=1 -timeout="${GO_TEST_TIMEOUT:-60m}"

echo "==> packaging metadata and owner rehearsal"
python3 scripts/verify-packaging-pins.py
python3 scripts/verify-packaging-pins.py --self-test
FINDCRYPTO="$CHECK_TMP/findcrypto" PYTHON=python3 \
	scripts/owner-rehearsal.sh "$REPO" "$CHECK_TMP/rehearsal"

echo "==> vulnerability scan"
go run "golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION" \
	-mode=binary "$CHECK_TMP/findcrypto"

if [ "$MODE" = core ]; then
	echo "$REQUESTED_MODE checks passed"
	exit 0
fi

echo "==> static analysis and fuzz smoke"
staticcheck ./...
for f in FuzzBIP39 FuzzKeys FuzzKeystore FuzzBrowserPassworder FuzzERC2335 FuzzExodusSECO FuzzBase58 FuzzZipLocalHeader; do
	go test ./detector -run NONE -fuzz "^$f\$" -fuzztime 15s
done

echo "==> password-recovery handoff"
FINDCRYPTO="$CHECK_TMP/findcrypto" JOHN="$JOHN_BIN" HASHCAT="$HASHCAT_BIN" \
	BTCR_DIR="$BTCR_DIR" PYTHON="${PYTHON:-python3}" \
	scripts/password-handoff.sh "$REPO" "$CHECK_TMP/handoff"

echo "==> release snapshot"
goreleaser check
goreleaser release --snapshot --clean --skip=publish,announce,sbom
scripts/verify-release-snapshot.sh

echo "full checks passed"
