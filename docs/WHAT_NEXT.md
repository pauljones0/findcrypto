# I found traces — what's next?

You ran a scan and got hits. This guide says what each kind of hit
means, what to do next (exact commands), and when to stop. Read the
two boxes first — they protect you from the two most common ways
people lose recoverable wallets.

> **SCAM SHIELD — read this before anything else.**
> You will be targeted. Fake "recovery services" reply to forum
> posts, run ads, and send DMs offering to unlock your wallet.
> Rules that never have exceptions:
>
> - **Never send your wallet file, keys, seed words, or password
>   guesses to anyone.** No legitimate tool or person needs them.
> - **Never type your seed into a website.** Restore only in
>   reputable wallet software, on your own machine, preferably
>   offline.
> - **Never pay upfront for "guaranteed" recovery.** Realistic
>   outcomes are uncertain; guarantees are the scam marker.
> - findcrypto itself never needs your secrets: it prints type labels
>   and byte offsets, never key or seed material.

> **WORK ON A COPY, OFFLINE IF YOU CAN.**
> If the wallet matters, stop writing to the source drive now —
> every write can overwrite deleted bytes. Ideally scan a clone or
> image, not the original (`docs/FORENSICS.md`). Keep carves and
> sidecars on encrypted storage, and delete them when done.

## How to read a hit

A hit line names a *trace*, not a wallet:

    Found 'bestblock' at /dev/sda in 4kB block at byte offset 4096

- `'bestblock'` is the needle: which detector fired (see below).
- `/dev/sda` is the target: where the bytes live. `Zipfile #0 ...`
  means inside a compressed file; `file=wallet.dat` (with `-fs`)
  names the filesystem entry.
- The offsets locate the bytes for carving. Only labels and offsets
  ever print — secret bytes stay in the carve files, if any.

Run `-report` on your hits for a summary with next steps per type:

    findcrypto -json /dev/sda > hits.jsonl
    findcrypto -report hits.jsonl

**Empty hits file?** An empty `hits.jsonl` means "clean" only when
the scan covered its target — a scan that read zero bytes produces
the same empty file, and a partial batch exits 0 with `[COMPLETE]`
while targets fail. Before celebrating, check the scan's stderr
for `[COMPLETE]` *without* a `WARNING`, its exit code (`1` means
the target failed or nothing was scanned), and — the durable
check — that every attempted target has a `complete` record in
the case log (`-verify-case-log` reports unscanned attempts as
`NOT SCANNED`). Never trust an empty hits file from a failed
run, and never treat zero detections as proof of a clean batch.

## 1. Marker hits — traces of a wallet database, no keys yet

Needles like `bestblock`, `defaultkey`, `orderposnext`,
`walletdescriptor`, `activeblock`, `channel.backup`.

**What it means:** a wallet file (or a piece of one) is or was at
that spot. Markers alone spend nothing — they say "dig here".

**Next:** carve around the hit and look at what came with it:

    findcrypto -extract-dir ./carve /dev/sda
    findcrypto -report hits.jsonl

Open the sidecar (`hit-NNNNNN.json`): it classifies the carved bytes
(`bdb`, `sqlite`, ...). If the carve holds database pages, findcrypto
reassembles them automatically into `hit-NNNNNN.salvage.db` — see
"Fragment salvage" in the README. Check the sidecar's `verdict`
first: `valid` is worth opening, `suspect` (with `reasons`) is a
lead, not a database. Then re-scan the carve: nearby
key, seed, or encrypted hits are the actual prize.

**Stop when:** wider carves (`-context`) keep showing markers only,
with no keys, seeds, or encrypted material. Markers without keys
are archaeology, not money.

## 2. Key hits — private key material nearby

Needles like `wif`, `xprv`/`tprv`/..., `xpub`/...

**What it means:** a checksum-validated key encoding sits at that
offset. `wif`/`xprv` shapes control funds; `xpub` shapes are
watch-only (they see addresses but spend nothing).

**Next:** carve it, then handle by type. Never print or paste the
key bytes — work from the carve file:

    findcrypto -extract-dir ./carve /dev/sda

- Private key (`wif`, `xprv`, ...): sweep the funds to a fresh
  wallet from an **offline** machine, then discard the exposed key.
  The old key is burned the moment it touched a scanned drive.
- Extended public key (`xpub`, `zpub`, ...): derive its addresses
  locally and check activity without ever exposing a secret:

    findcrypto -watch ./carve/hit-000003.bin -watch-out addrs.csv

  See `docs/WATCH_ONLY.md`. Activity comes only from an explicitly selected
  Esplora node (`-balance-endpoint`) — never paste the xpub into a website.
  Treat `used=true` as evidence even when the current balance is zero.

**Stop when:** the key is testnet (`tprv`/`wif-testnet` — worthless
play money) or the carve shows the encoding was a fragment that
fails validation on closer look.

## 3. Seed-phrase hits — recovery words nearby

Needles like `bip39-12`, `bip39-24-near-miss`, `bip39-unordered`,
`electrum-seed`, `slip39-20`.

**What it means:** 12–24 dictionary words in a validating (or
near-validating) arrangement. Exact hits are strong; `near-miss`
has 1–2 wrong/missing words; `unordered` is a word pile that might
be a scrambled phrase — or word salad.

**Next:** carve it. Owner recovery can print the words, on your own
machine only, after a loud warning:

    findcrypto -extract-dir ./carve /dev/sda
    findcrypto --reveal -json ./carve/hit-000001.bin

Never share, paste, or log `--reveal` output. Restore exact phrases
in reputable wallet software, offline.

**1–2 words missing or smudged? Complete them offline.** A near-miss
with 1–2 gaps is enumerable (2,048 tries for one gap, ~4M for two —
seconds), most-likely first, with "did you mean" typo correction. A phrase
made entirely of BIP39 words but failing its checksum also gets a bounded
one-position substitution search, covering one wrong-but-valid word:

    findcrypto --reveal -json ./carve/hit-000001.bin |
      findcrypto -report - -complete --reveal \
        -known-addresses public-addresses.txt \
        -recovery-start 0 -recovery-count 20

The left side re-scans with words attached (required—completion needs the
words), and the pipe avoids saving reveal JSON containing live seed material.
Put one public address per line in `public-addresses.txt`; checksummed
Bitcoin/Litecoin/Dogecoin Base58, Bech32, EIP-55 EVM, Cosmos, and 32-byte Solana
Base58 forms are validated. The second command derives all supported named
profiles and 20 bounded slots entirely offline. Unmatched candidate phrases
stay hidden; a positive match prints its chain, profile, path, address, and
candidate phrase.

If you do not have a known address, use `-complete-out identities.txt` instead.
On Unix this atomically writes an owner-only handoff containing three Bitcoin
watch-only account keys and comment-only EVM, Solana, Litecoin, Dogecoin, and
Cosmos Hub addresses—never phrases or private keys:

    findcrypto --reveal -json ./carve/hit-000001.bin |
      findcrypto -report - -complete --reveal -complete-out identities.txt

    findcrypto -watch identities.txt -watch-out addrs.csv

For a known BIP39 passphrase on Unix, create an owner-only file, type exactly
one non-empty UTF-8 line without a BOM in an offline editor, and pass its path.
The value is NFKD-normalized and never printed, logged, or placed in the
handoff:

    (umask 077; touch bip39-passphrase.txt)
    chmod 600 bip39-passphrase.txt
    ${EDITOR:-vi} bip39-passphrase.txt
    findcrypto --reveal -json ./carve/hit-000001.bin |
      findcrypto -report - -complete --reveal \
        -known-addresses public-addresses.txt \
        -bip39-passphrase-file bip39-passphrase.txt \
        -recovery-count 20

An empty file means no passphrase and is refused—omit the flag for the standard
empty BIP39 passphrase. Windows passphrase files are also refused until
FindCrypto can verify an owner-only DACL instead of trusting the read-only bit.

Use `-recovery-profiles` to narrow the default set (`bitcoin-standard`,
`evm-standard`, `solana-standard`, `litecoin-bip44`, `dogecoin-bip44`,
`cosmos-hub`) and `-recovery-start` to move the bounded window. See
`docs/CHAIN_SUPPORT.md` for exact paths and limits.

Smudged paper, no scan? Write the words you have into an owner-only text file
with `xxxx` for each missing word (any non-word letter-run works —
never a real word). Use an offline editor so the words never enter shell history,
then pipe the reveal scan directly into completion:

    (umask 077; touch smudged.txt)
    chmod 600 smudged.txt
    ${EDITOR:-vi} smudged.txt
    findcrypto --reveal -json smudged.txt |
      findcrypto -report - -complete --reveal

For scrambled phrases, 3+ missing words, or a passphrase that must itself be
searched rather than supplied,
take the carve to
[BTCRecover](https://github.com/3rdIteration/btcrecover), which
searches permutations and GPU word combinations offline enumeration
cannot reach — findcrypto refuses those loudly instead of guessing.

**How to interpret a miss:** `Known-address match: no candidate matched` is
inconclusive, not a clean bill of health. Check whether completion output was
truncated, whether a BIP39 passphrase existed, whether the wallet used a later
index, and whether its wallet-specific path differs from the named presets.
Likewise, `used=false` across one Bitcoin gap window is not proof that a phrase
is wrong. Stop one bounded attempt when its stated assumptions are exhausted;
do not destroy the original evidence or rule out the candidate solely from an
empty window. Positive address history—even with zero current balance—is the
strong signal. A single SLIP39 share with no path to the threshold still cannot
recover anything, and anyone asking for secrets or money triggers the scam
shield at the top.

## 4. Encrypted hits — the wallet needs its password

Needles like `crypted_key`, `eth-keystore`, `erc2335-keystore`,
`exodus-seco`, and `browser-passworder-vault` (old saved hits may still contain
the legacy label `metamask-vault`).

**What it means:** an encrypted wallet or vault. The keys exist but
are locked; without the password (or a crackable one) nothing moves.

**Next:** extract crack-ready hashes from a carve or wallet copy —
never the scanned device itself:

    findcrypto -hashes ./carve/hit-000001.bin

Then follow `docs/PASSWORD_RECOVERY.md` (hashcat, John, BTCRecover). Exodus
SECO containers export Hashcat mode 28200 after the declared
metadata+length+blob checksum
verification. ERC-2335 is detected and carved but deliberately reports that no
cracker export is supported.
If you half-remember the password, `-tokenlist` builds the starting
BTCRecover tokenlist from the words near the hit:

    findcrypto -tokenlist ./carve/hit-000001.bin -tokenlist-out tokens.txt
Start with passwords you have actually used; strong unique forgotten
passwords are effectively unrecoverable, and anyone promising
otherwise is selling something (see the scam shield).

**Stop when:** read stderr first. A format-specific skip means the complete
artifact is unsupported or damaged and explains whether widening can help; a
bare `No crack material found` can justify a wider carve. Stop password guesses
when your realistic space is exhausted. Truncated or unverified hashes are
never emitted because they only waste crack time.

## 5. Secrets-profile hits — leaked credentials, not wallets

Needles like `pem-private-key`, `aws-access-key`, `github-token`
(only with `-profile=secrets`).

**What it means:** a private key block or cloud credential. No
coins directly — but on a shared or stolen machine these are the
attacker's prize. A `verified` key block only means it parses
correctly — not that the key works or that anyone tested it live.

**Next:** treat any carve as a live secret (encrypted storage,
delete after) and rotate: private keys get replaced and purged
from wherever they leaked; cloud keys get revoked in IAM / at
github.com/settings/tokens with a misuse check. Full checklist:
`docs/SECRETS_PROFILE.md`.

**Stop when:** everything found is revoked/rotated and the leak
source is cleaned. There is no "recover funds" step here — only
containment.

## When to give up (for real)

- The drive was SSD-TRIMmed, fully overwritten, or encrypted with a
  lost key: no tool recovers those bytes, including this one.
- Months of realistic password guesses failed on a strong password.
- Only filename/marker hits remain after wide carves.
- Someone asks for money or secrets to continue: that is the scam,
  not the solution. Walk away.
