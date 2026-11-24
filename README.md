# FindCrypto

Recovers cryptocurrency wallet traces from devices, forensic images, files,
archives, and live directory trees. Bitcoin recovery remains the deepest path,
but the scanner is deliberately multichain and format-driven.

This project was formerly `findbtc` / `findbtc_sandbox`. The primary command and
repository are now `findcrypto`; release builds keep a `findbtc` compatibility
command for existing scripts. See [the migration guide](docs/MIGRATION.md).
The recovery ideas carried over from `wheres-my-wallet`—and the unsafe parts
deliberately not copied—are recorded in
[docs/WHERES_MY_WALLET.md](docs/WHERES_MY_WALLET.md).

The tool can find wallets even if;

- The wallet was deleted, but not overwritten
- The file system is corrupted and inaccessible
- The device has been reformatted
- The wallet has been partially overwritten
- The wallet is inside a .zip or .tar.gz file, including 
  nested in multiple levels of compressed files
- The zip's central directory is lost: single entries are still carved from
  local file headers

It looks for byte traces of legacy wallets (`bestblock`, `defaultkey`,
`keymeta`, `hdseed`, `crypted_key`, ...), modern descriptor wallets
(`walletdescriptor`, `activeblock`), checksum-validated BIP39 seed phrases
(12/15/18/21/24 words), near-miss phrases with missing or mistyped words,
WIF and extended (`xprv`/`xpub`/...) keys with
base58check validation, Ethereum keystore files (validated by structure),
Electrum seeds and wallet files, checksummed output descriptors, SLIP39
shares, lnd channel-database markers, MetaMask vaults,
validated Solana CLI keypair files, and the `wallet.dat` file name. Only key and phrase
types are ever printed; the secrets themselves stay out of logs and output.
The exact discovery/recovery/activity boundary for each ecosystem—and the next
chain adapters—is tracked in [the chain support matrix](docs/CHAIN_SUPPORT.md).

## Installing

During the rename, install the current generic command directly from the main
branch. That requires Go 1.26 or newer (the current supported old-stable line):

    go install github.com/pauljones0/findcrypto@main
    sudo findcrypto /dev/sda

Contributors using [mise](https://mise.jdx.dev/) get the Go release toolchain
pinned by `.mise.toml`; external tool pins live in `scripts/tool-versions.env`.
Run `scripts/check.sh core` before sharing changes;
on Linux, `scripts/check.sh full` additionally requires and executes the real
BDB/FAT/exFAT/XFS oracles, external password tools, fuzz smoke, static analysis,
and verified GoReleaser packages/containers. `scripts/check.sh floor` repeats
the core checks with the pinned minimum Go toolchain.

The first tagged `findcrypto` release can be built manually as x86-64 and
ARM64 archives for Linux, macOS, and Windows, Linux deb/rpm packages, and
`ghcr.io/pauljones0/findcrypto`. Release assets include checksums and SPDX
SBOMs. Hosted GitHub Actions and attestations are intentionally not used; see
[docs/RELEASE.md](docs/RELEASE.md) for the maintainer-run process.

The existing v0.2 package channels remain pinned compatibility paths while the
generic channels are established. They install the old `findbtc` command, whose
behavior is retained in new releases:

    # macOS / Linux Homebrew
    brew tap pauljones0/findbtc
    brew install pauljones0/findbtc/findbtc

    # Windows Scoop
    scoop bucket add findbtc https://github.com/pauljones0/scoop-findbtc
    scoop install findbtc

Do not use guessed `homebrew-findcrypto`, `scoop-findcrypto`, or Winget
identifiers: those repositories/packages do not exist yet. Their immutable
manifests are checked by `scripts/check.sh`; hosted native install smoke was
removed with GitHub Actions, so verify a legacy channel on its native OS before
changing its manifest. Full transition details are in
[docs/MIGRATION.md](docs/MIGRATION.md).

## Usage

    findcrypto [-s start-offset] [-json] [-extract-dir DIR [-context BYTES]] [-targets FILE] TARGET [TARGET ...]

    # Eg. scan a disk, printing human-readable hits:

    findcrypto /dev/sda

    # Eg. machine-readable hits with exact byte offsets:

    findcrypto -json /dev/sda > hits.jsonl

    # Eg. carve 1MB around every hit into ./carve/ for forensic follow-up:

    findcrypto -extract-dir ./carve /dev/sda

    # Eg. secret hygiene on a repo or laptop (adds non-wallet matchers):

    findcrypto -profile=secrets -walk ~/src > secrets.jsonl

    # Eg. scan a piped image (same hits as scanning the file):

    dd if=/dev/sda bs=1M | findcrypto -json - > hits.jsonl

    # Eg. scan several images in one run, one hits file out:

    findcrypto -json -case-log case.jsonl img1.E01 img2.raw > hits.jsonl
    # or list the targets in a file (one path per line):
    findcrypto -json -case-log case.jsonl -targets batch.txt > hits.jsonl
    # Flags precede targets (parsing stops at the first positional);
    # use -- before a target whose name starts with -.

A cold rehearsal of the whole owner path on synthetic disposable
media (`scripts/owner-rehearsal.sh` stages `media/` and runs this
block verbatim, then asserts coverage, case-log verification, and
that no secret bytes leak into default output):

<!-- owner-rehearsal:start -->
```sh
findcrypto -advise media/owner.img
findcrypto -json -case-log case.jsonl -extract-dir ./carve media/owner.img media/decoy.bin > hits.jsonl
findcrypto -report hits.jsonl
findcrypto -hashes media/eth-pbkdf2.json
findcrypto -verify-case-log case.jsonl
```
<!-- owner-rehearsal:end -->

Not sure which mode fits your target? Ask first — it only inspects,
never scans:

    findcrypto -advise /dev/sda

Key-file advice lists validated public-key versions and fingerprints.
Malformed keys keep the raw-scan recommendation.

Detections print to stdout; logs, progress and the final `[COMPLETE]` line go
to stderr, so `-json` output stays parseable. Exit codes are a contract:

| Code | Meaning |
| ---- | ------- |
| 0 | The run completed and covered its target — hits or not. A `-walk` that scanned at least one file, or a multi-target run that scanned at least one target, exits 0 even when others failed (failures print loudly with a `WARNING`). |
| 0 | Follow-up modes (`-report`, `-hashes`, `-tokenlist`, `-salvage`, `-watch`) report readable-but-empty input on stdout and exit 0 — for example `No extended public keys in FILE`. Only missing or unreadable input exits 1. |
| 1 | Runtime error or zero coverage: the root target could not be read (missing, unreadable, vanished mid-run), or a `-walk` / multi-target run scanned nothing at all. The reason is on stderr. |
| 2 | Bad flags/usage. |
| 3 | Hits found — but only with `-fail-on-hit`, which gates local checks and pre-commit hooks (see [docs/SECRETS_PROFILE.md](docs/SECRETS_PROFILE.md)). |

A bad nested archive inside a readable root stays a warning (exit 0):
only the root target can fail the run.

Progress lines print to stderr at most every 10 seconds (never to
stdout, so pipes stay clean). Known-size targets show percent,
throughput, and an ETA once past a 5-second warmup; the ETA follows
the measured average, so it rises when the scan slows rather than
holding a stale low figure. Unknown-size targets show megabytes
scanned:

    [41.27% 12.4MB/s ETA 3m12s]
    [87mb/??mb 9.8MB/s]

Throughput is per-target (a `-walk` line covers the file in flight).
`-resume` announces its position the same way:

    [main] Resuming /dev/sda at byte offset 123456 (continuing at 41%)

The line shape is a versioned
contract: [schema/hits-v1.json](schema/hits-v1.json), documented in
[docs/HITS_SCHEMA.md](docs/HITS_SCHEMA.md). Each carved hit lands in
`hit-NNNNNN.bin` with a `hit-NNNNNN.json` sidecar holding the same detection
plus a classification of the carved bytes (`sqlite`, `bdb`, `gzip`, `zip`,
`text`, `high-entropy`, ...).
Never carve onto the device being scanned.

### Piped input

Raw scans and the secrets profile accept `-` for stdin, so forensic
triage works over pipes the tool could never seek:

    dd if=/dev/sdb bs=4M | findcrypto -json - > hits.jsonl
    ssh lab 'dd if=/dev/sda bs=4M' | findcrypto -profile=secrets - > secrets.jsonl

Detections are byte-identical to scanning the same bytes from a file:
offsets are pipe offsets (byte 0 is the first byte read), and only
the target label differs (`"target":"stdin"`, echoed in the
human-readable description; case logs record kind `"stdin"` instead
of `"raw"`). `-s` skips leading pipe bytes; `-extract-dir` carves
work as usual.

Pipes cannot be re-read, so the whole stream is spilled to a temp
file before scanning starts (retries and carves re-open it). The
spill lives in the OS temp dir as `findcrypto-stdin-*` (`$TMPDIR` on
Unix, `%TMP%` on Windows — point it at a big volume for large
images) and is removed when the scan returns, success or failure —
a crash may leave it behind for manual cleanup. The spill is capped
at 1 TiB as a backstop against runaway pipes; past the cap the scan
fails loudly rather than truncating, and a full temp disk fails
loudly mid-spill. Spill progress notes print to stderr (one line per
GiB) so large pipes stay visibly alive.

One exception to file parity: forensic containers piped in (EnCase
E01 sets, split raw segments) scan as raw bytes — segments cannot
decode from one flat stream. The scan warns loudly when piped input
carries EWF magic; pass the image file itself for a decoded scan.

Modes that need what a pipe cannot give refuse with exit 1 instead of
mis-scanning: `-fs` and `-unallocated-only` (filesystem offsets),
`-walk` (a directory), `-checkpoint`/`-resume` (a journaled path —
a journal naming a deleted temp file could never resume).

### Triage

A scan can produce hundreds of hits. Summarize them offline, without
rescanning:

    findcrypto -json /dev/sda > hits.jsonl
    findcrypto -report hits.jsonl

The report answers "is there anything here worth pursuing": per-type
counts with duplicates merged, per-hit confidence, encryption flags,
and prioritized next steps, with hits grouped under one section per
target (each with its hit count and byte-offset span). `-report -`
reads from stdin; add `-json` for the machine-readable report. Like the
scanner, the report prints type labels only — never key or seed material.
Every report ends with a coverage line instead of a clean bill of
health: listed hit targets are not scan coverage — clean targets
leave no trace in the hits, failed ones neither, and a partial batch
exits 0 with `[COMPLETE]` while targets fail. Confirm every attempted
target has a `complete` record in the case log before trusting a
report. If the hits are yours
and you don't know what to do next, read
[docs/WHAT_NEXT.md](docs/WHAT_NEXT.md) before anything else.

> **SCAM SHIELD.** Fake "recovery services" target people who just
> found wallet traces. Never send your wallet file, keys, seed words,
> or password guesses to anyone — no legitimate tool or person needs
> them. Never pay upfront for "guaranteed" recovery. Work on copies,
> offline. Details in [docs/WHAT_NEXT.md](docs/WHAT_NEXT.md).

### Password recovery

Encrypted hits can carry crack-ready password hashes. Extract them from a
carve or wallet copy (never the scanned device itself):

    findcrypto -hashes ./carve/hit-000001.bin

Scans with `-extract-dir` already attach any `hashes` found in each carve
to the detection and its sidecar. When the password is only half
remembered, `-tokenlist` turns the words near a hit into a starting
BTCRecover tokenlist (case mutations included):

    findcrypto -tokenlist ./carve/hit-000001.bin -tokenlist-out tokens.txt

See [docs/PASSWORD_RECOVERY.md](docs/PASSWORD_RECOVERY.md) for the
end-to-end runbook (hashcat, John the Ripper, BTCRecover) — every command there
runs verbatim through the local password-handoff harness against real tools.

### Near-miss seed phrases

Recovery input is rarely a perfect phrase, so the scanner also reports
near-misses: phrase-length windows with 1–2 unknown words
(`bip39-12-near-miss`, ...), and runs of 12+ valid words with no
validating window (`bip39-unordered`, possibly a phrase in the wrong
order or one wrong-but-valid dictionary word). Near-miss output is positions and counts only, e.g.
`gaps=[3] typo=[14] validating=[1]` — the gap positions, per-gap
typo candidates within edit distance 2, and how many of those validate
the checksum. Overlapping evidence resolves exact first, then unordered
runs, then near-miss windows, so one location never reports twice.
Measured false-positive bar: zero hits on 1MB of random
bytes and on needle-free prose (LICENSE, main.go, fixtures).
README and GOALS name needle labels on purpose, so the controlled repository
corpus test expects hits there and on wallet fixtures.

Owner recovery can print the actual words with `--reveal`, which attaches
them to BIP39 detections (stdout `-json` included) after a loud warning.
Never share, paste, or log `--reveal` output.

One or two words missing or smudged, or one wrong-but-valid word, is enumerable offline
(checksum-gated, most-likely first, with typo correction) as a
`-report` follow-up — no new mode:

    findcrypto --reveal -json ./carve/hit-000001.bin > near.jsonl
    findcrypto -report near.jsonl -complete --reveal -complete-out keys.txt
    findcrypto -watch keys.txt -watch-out addrs.csv

Candidates print on the local terminal only; the keys file contains Bitcoin
watch-only account keys plus comment-only EVM and Solana public addresses,
never phrases or private keys. Its Bitcoin keys feed `-watch` with no
copy-paste. Past
two missing words the tool refuses loudly and points at
[BTCRecover](https://github.com/3rdIteration/btcrecover), which also
owns scrambled-phrase reordering. Full recipe and stop rules:
[docs/WHAT_NEXT.md](docs/WHAT_NEXT.md).

### Fragment salvage

When a carve holds database pages, findcrypto reassembles them automatically:
Berkeley DB pages order by their page numbers (gaps zero-filled), SQLite
pages validate into page sets grouped into contiguous runs. Each success
writes `hit-NNNNNN.salvage.db` beside the carve, and the sidecar records a
page map with the source offset of every page. Any file can be analyzed
directly:

    findcrypto -salvage ./carve/hit-000001.bin -salvage-out wallet.salvage.db

Salvage needs at least two pages of one database; otherwise the window
carve stands. SQLite order is certain only for a single page-1-led run —
otherwise the page map is the deliverable. Pages destroyed by overwrite or
SSD TRIM cannot be recovered by any tool; overflow and freelist pages are
not identified.

Every salvaged image carries a `verdict` in the sidecar (`salvage.verdict`,
with `reasons`): `valid` means the structure predicts the file opens in
the real database tool — try it (`db_verify`/your wallet software for
BDB, `sqlite3 file.db "PRAGMA quick_check"` for SQLite). `suspect` means
a concrete problem was found (missing pages, page-count mismatch,
uncertain order) — treat the image as a lead for manual carving, not a
database, and read `reasons` before spending effort. `-report` counts
suspect salvages separately. Verdicts are structural predictions, checked
against `db_verify` and `quick_check` on the fixture set — not proofs.

### Watch-only triage

Extended public keys derive their addresses locally — no website paste,
no network:

    findcrypto -watch ./carve/hit-000003.bin -watch-out addrs.csv

Accepts a carve, a key file, or `hits.jsonl` (whose carves are searched).
Exports 20 addresses per chain (external + change) as CSV or JSON, with
the script type following the key version (`xpub`→P2PKH, `ypub`→P2SH,
`zpub`→bech32, testnet equivalents). Full keys never appear in the
export; private keys are refused. An opt-in `-balance-endpoint` flag fills
activity from your own Esplora node: confirmed and mempool transaction counts,
funded/spent totals, current balance, and an explicit `used` signal. A spent
zero-balance address therefore remains visible instead of looking unused. See
[docs/WATCH_ONLY.md](docs/WATCH_ONLY.md).

### More wallet formats

Beyond Core wallets and BIP39, the scanner validates:

- **Electrum seeds and files.** 12-word new-style seeds checked against
  the Electrum version prefixes (standard/segwit/2fa), and wallet JSON
  via its seed_version plus wallet_type markers. Old-style Electrum
  seeds (different wordlist, weak check) are out of scope.
- **Output descriptors.** Parenthesized descriptors with a valid
  Core checksum. Descriptor text never prints — it can embed private
  keys — only the hit location.
- **SLIP39 shares.** 20-word (128-bit) and 33-word (256-bit) Shamir
  shares with a valid RS1024 checksum, extendable or not. One share
  alone recovers nothing; gather the threshold.
- **Lightning (lnd).** channel.db bucket markers and the channel.backup
  / channel.db file names. The backup file itself is encrypted, so only
  its name is detectable; buckets say a database is near.
- **MetaMask vaults.** Encrypted vault objects (plain or JSON-escaped
  as in browser storage), validated by field shape and decoded
  lengths. Always flagged as needing its password.
- **Solana CLI keypairs.** JSON arrays containing exactly 64 Ed25519
  keypair bytes. The public half must derive from the private seed, which
  rejects arbitrary 64-number arrays; the bytes themselves never print.

Every format above reports labels and offsets only, carries a triage
classification with next steps in `-report`, and holds the same
false-positive bar: silence on 1MB of random bytes and on this repo's
own prose, enforced by per-format tests. Validated seeds outrank the
weaker unordered hint when they overlap, and Electrum windows inside a
longer exact BIP39 phrase defer to it.

### Filesystem-aware recovery

Raw scanning loses filenames and wastes time on live data. For NTFS and
ext volumes, `-fs` inventories live and deleted entries with names and
scans deleted files' content with filenames stamped on every hit, while
`-unallocated-only` skips everything still allocated:

    findcrypto -fs ./evidence/sdb1.img -json > fs-hits.jsonl
    findcrypto -unallocated-only /dev/sdb1

For full-disk captures, omit `-fs-offset` and the MBR/GPT partition
table is followed automatically (every NTFS/ext/FAT/exFAT/XFS partition is scanned);
pass `-fs-offset` only to pin one volume boot sector by hand.
Range scans take `-checkpoint`/`-resume` too: the journal records
`(range_index, offset)`, and resume refuses loudly if the volume's
range list changed since. Reports show
`file=` for attributed hits. SSDs
with TRIM erase freed blocks within seconds — metadata then names files
whose bytes are gone; see [docs/FILESYSTEMS.md](docs/FILESYSTEMS.md).

Unreadable sectors are retried, then skipped and logged with their byte
ranges, so one bad spot never aborts a scan. For long scans, `-checkpoint
FILE` journals progress every 1MB; if the run is interrupted, `-resume`
continues from the journal instead of starting over.

### Directory sweeps

Sweep a live system, laptop, or repo with the same detectors:

    findcrypto -walk /home/user -json > sweep.jsonl
    findcrypto -report sweep.jsonl

Symlinks are not followed by default, one unreadable file never aborts
the sweep, and each file appends its own case-log record. Repeat
sweeps suppress reviewed findings with `-baseline known.jsonl` (see
[the secrets profile](docs/SECRETS_PROFILE.md)). See the
[runbook](docs/LIVE_SWEEP.md) for policy and live-system notes.

### Forensic casework

EnCase E01 and SMART S01 sets (pass the `.E01`/`.s01`) and split raw
images (`base.001`, …) scan directly, with decoded bytes cross-checked
against the set's stored MD5. EWF2 (`Ex01`/`Lx01`) is refused with a
conversion pointer — see [docs/FORENSICS.md](docs/FORENSICS.md). `-case-log` records source hashes, flags, bad-sector ranges, and
counts per scan; `-verify-case-log` re-hashes the evidence behind the
log so a reviewer can confirm nothing changed; `-dfxml` exports hits
as DFXML 1.1.1 for Autopsy and case pipelines:

    findcrypto -json -case-log case.jsonl evidence.E01 > hits.jsonl
    findcrypto -verify-case-log case.jsonl
    findcrypto -dfxml hits.jsonl > hits.dfxml

Always work from an acquisition behind a write-blocker, never the
original; see [docs/FORENSICS.md](docs/FORENSICS.md) for the end-to-end
workflow. Each release ships with checksums and an SBOM; because builds are
maintainer-run rather than hosted-attested, independently reproduce sensitive
casework builds as described in [docs/RELEASE.md](docs/RELEASE.md).

### Shell completion and man page

The deb/rpm packages install bash, zsh, and fish completions plus a
man page (`man findcrypto`), all generated from the real flag table —
every flag is covered by construction. From any other install, print
them straight from the binary:

    findcrypto -gen-completion=bash   # or zsh, fish
    findcrypto -gen-man | man -l -

The man page's SEE ALSO links the guides no other doc points at
(benchmarks, pipeline ingest, resource bounds), installed under
`/usr/share/doc/findcrypto/`.

## License

GPL
