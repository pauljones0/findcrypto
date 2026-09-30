# Worktree reconciliation — 2026-09-29

All nine side worktrees were inspected against `eb72f75` before merging.
Unpublished changes were backed up outside the checkout and committed
on named reconciliation branches, preserving their original contents.
The completed histories were merged into main in `107d218`.

| Original branch or detached head | Work | Result / completed head |
| --- | --- | --- |
| `acceptance/no-drop-probes` (`9f4e651`) | Same-cap retry convergence and EOF-flush coverage acceptance tests | Later main tests retain the intended coverage with union accounting and toolchain-independent nested counts; reconciled in `035873c`. |
| `review-followup/pubgate-race-determinism-nits` (`10e54b3`) | Serialized logging, deterministic congested tests, dead-field cleanup | Already an ancestor of main; fast-forwarded to `eb72f75`. |
| Detached `bf3c984` | Nested-publication torture proofs, plus staged retry tests | Original staged tests preserved in `92a7d13`; completed versions retained from main in `8bcab9b`. |
| `proposal/goals43plus` (`9d23a0e`) | Ranked advice, FAT filename, and multi-volume checkpoint proposal | Proposal bytes already match main exactly; original history merged in `61195b9`. All three proposed features have implementations and tests. |
| `acceptance/no-drop-probes-union` (`e944f25`) | EOF retry set-union and duplicate-emission checks | Main additionally filters root hits whose presence depends on the flate toolchain; reconciled in `487af28`. |
| `goal43-advise-routing` (`b980f74`) | Follow-up routing, validators, public-key fingerprints, EWF flavor labels, empty-vs-error exits | Main already contains most routing and broader CLI checks. Missing validator behavior, fingerprints, and flavor labels completed in `e0d0654`. |
| Detached `6385b0a` | Uncommitted advice integration and CLI tests | Entire unpublished patch reverse-applies to main. Snapshot retained in `7cdd909`, reconciled in `8140c7f`. |
| Detached `3c18382` | Deleted FAT long-name recovery, fixtures, oracle tests, filename stamps | Test file exactly matches main; implementation differs only by a later explanatory comment. Snapshot retained in `f9a6590`, reconciled in `89a9423`. |
| Detached `21f1111` | Multi-volume filesystem checkpoint implementation and recovery tests | Main adds empty-list journal validation, production filename ownership, and durable frontier receipts. Snapshot retained in `14a0201`, reconciled in `d8b653b`. |

## Differences that required finishing

The original advice branch parses public keys before recommending watch
mode. Main only checked their Base58 checksum, so it could recommend a
mode that rejects the file. New fixtures independently establish that
uncompressed keys, coordinates outside the curve, and invalid master
metadata pass extraction but fail watch parsing. Each reproduced the
misroute before the fix; afterward these files retain raw scanning.
Mixed valid/invalid inputs route to watch with a count of usable keys.

The branch's EWF segment flavor labels and published-vector fingerprint
checks also failed against main before reconciliation. Those behaviors
were retained while preserving main's multi-key advice, large-target
checkpoint suggestions, strict bounded sniffing, and fuller CLI tests.
Advice prints key versions and fingerprints, never the key strings.

## Why older acceptance assertions were superseded

The earliest EOF-flush probe expected the retry alone to re-emit all
baseline hits. The subsequently reviewed no-drop scheduler deliberately
banks completed members and defers them on retry. The retained test
checks that the union of both attempts equals the cold baseline and
that their intersection is empty. This is a contract correction, not
acceptance of missing coverage. Same-cap retry convergence, stale-byte
identity refusal, and real-kill tests remain present.

FAT and checkpoint drafts were compared as whole files, not just by
branch names or commit IDs. Their implementations and tests had already
landed; selecting the later main versions preserves the subsequent
fixes and XFS integration.

## Validation and cleanup

Validation covers formatting, build, vet, the full Go suite, and race
checks for advice, retry acceptance, FAT recovery, and filesystem range
scanning. The full suite includes real-kill batch and filesystem resume,
changed-input and journal refusal, publication torture, CLI follow-up
exit checks, and available filesystem oracle checks.

The full suite, build, vet, formatting, and focused race checks passed.
Sleuth Kit was initially absent, so its oracle tests skipped. A temporary
unpacked Ubuntu Sleuth Kit 4.12.1 toolchain then independently verified
FAT12/16/32 deleted names and content, along with exFAT fixtures; the XFS
oracle passed in the same run. Linux CI now installs `sleuthkit` alongside
the existing BDB and XFS tools, keeping those checks active after push.

Every completed worktree head is an ancestor of the merged main, and
each checkout is clean before removal. Completed side checkouts are
removed without force; branch refs and their original/snapshot histories
remain recoverable through main. Patch backups and the original
inventory manifest are also retained outside the repository.
