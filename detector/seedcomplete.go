package detector

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// Offline seed completion (Goal 32). Given a partial BIP39 phrase — 1–2
// words missing anywhere, including the checksum word — enumerate the
// checksum-valid completions offline, most-likely first, and hand the
// winners to the existing watch-only flow as account keys. Past 2
// missing words the search is billions of tries: refuse loudly and
// point at BTCRecover/GPU instead of pretending.
//
// Shape (per the goal's bias): a -report follow-up on partial-seed
// (near-miss) hits, not a new mode. The CLI feeds Detection.Words from
// --reveal hits into CompleteSeed; this file stays a pure library.
//
// Privacy: completions are live secrets. They are returned to the
// caller (which prints them only under --reveal with loud warnings)
// and never logged. SeedToAccounts touches transient private material
// in memory only — seeds and private keys are zeroized after use and
// never leave the function except neutered to public account keys.

// Completion result caps.
const (
	// CompleteDefaultMax is the shown-completion budget when the caller
	// passes maxResults <= 0: the 128 most-likely candidates.
	CompleteDefaultMax = 128
	// CompleteHardMax clamps maxResults: beyond 10k candidates the
	// terminal listing (and the PBKDF2 bill behind -complete-out) stops
	// being triage and starts being a dump. Total stays exact.
	CompleteHardMax = 10000
)

// ErrTooManyMissing marks the loud refusal past 2 missing words.
var ErrTooManyMissing = errors.New("too many missing words for offline completion")

// PartialSeed is a seed-length word list with gap positions: tokens that
// are not BIP39 words (case-insensitive), e.g. smudged words transcribed
// as "xxxx" or typo'd words from a near-miss hit.
type PartialSeed struct {
	Words  []string // verbatim input words
	Length int      // seed length (12/15/18/21/24)
	Gaps   []int    // positions holding non-wordlist tokens
}

// Completion is one checksum-valid completion, most-likely first.
type Completion struct {
	Words     []string // full restored phrase
	Fill      []string // replacement words
	Positions []int    // replaced positions aligned with Fill
	Score     int      // edit-distance score (lower = more likely)
}

// Correction is a "did you mean" suggestion for one typo-like gap.
type Correction struct {
	Position int      // gap position in the phrase
	Token    string   // the token that was there
	Suggest  []string // validating neighbors, most-likely first
}

// SeedCompletion is the full answer for one partial phrase.
type SeedCompletion struct {
	Partial     PartialSeed
	Shown       []Completion // most-likely first, capped at maxResults
	Total       int          // exact checksum-valid count (never capped)
	Truncated   bool         // Total > len(Shown)
	Corrections []Correction // "did you mean" per typo-like gap
}

// CompleteSeed enumerates the checksum-valid completions of a partial
// phrase, most-likely first. Unknown-token gaps use the scanner's capped
// typo-distance ordering. When every token is a BIP39 word but the checksum
// fails, the bounded recovery path substitutes exactly one word and orders
// candidates by exact edit distance, position, then wordlist order. Shown
// caps at maxResults (<=0 means CompleteDefaultMax, above CompleteHardMax
// clamps); Total is always the exact count. Three or more gaps refuse with
// ErrTooManyMissing.
func CompleteSeed(words []string, maxResults int) (*SeedCompletion, error) {
	p, err := parsePartialSeed(words)
	if err != nil {
		return nil, err
	}
	if len(p.Gaps) > 2 {
		return nil, tooManyMissingError(p)
	}
	if maxResults <= 0 {
		maxResults = CompleteDefaultMax
	}
	if maxResults > CompleteHardMax {
		maxResults = CompleteHardMax
	}
	if len(p.Gaps) == 0 {
		return completeKnownWords(p, maxResults)
	}
	base := make([]uint16, p.Length)
	for i, w := range p.Words {
		if idx, ok := bip39WordIndex[strings.ToLower(w)]; ok {
			base[i] = idx
		}
	}
	// Per-gap candidate order: (capped distance, wordlist index).
	orders := make([][]uint16, len(p.Gaps))
	dists := make([][]int, len(p.Gaps))
	for gi, g := range p.Gaps {
		tok := strings.ToLower(p.Words[g])
		order := make([]uint16, len(bip39Words))
		dist := make([]int, len(bip39Words))
		for i, w := range bip39Words {
			order[i] = uint16(i)
			dist[i] = cappedDistance(tok, w)
		}
		sort.Slice(order, func(a, b int) bool {
			if dist[order[a]] != dist[order[b]] {
				return dist[order[a]] < dist[order[b]]
			}
			return order[a] < order[b]
		})
		orders[gi], dists[gi] = order, dist
	}
	res := &SeedCompletion{Partial: p}
	if len(p.Gaps) == 1 {
		completeOneGap(res, base, p.Gaps[0], orders[0], dists[0], maxResults)
	} else {
		completeTwoGaps(res, base, p.Gaps, orders, dists, maxResults)
	}
	res.Corrections = suggestCorrections(p, dists, res.Shown)
	return res, nil
}

// parsePartialSeed validates the seed length and locates gaps. A token
// is known iff it lowercases to a wordlist word, matching the scanner.
func parsePartialSeed(words []string) (PartialSeed, error) {
	p := PartialSeed{Words: append([]string(nil), words...), Length: len(words)}
	okLen := false
	for _, l := range bip39Lengths {
		if len(words) == l {
			okLen = true
			break
		}
	}
	if !okLen {
		return p, fmt.Errorf("cannot complete %d words: not a seed length (want 12/15/18/21/24)", len(words))
	}
	for i, w := range words {
		if _, ok := bip39WordIndex[strings.ToLower(w)]; !ok {
			p.Gaps = append(p.Gaps, i)
		}
	}
	return p, nil
}

// tooManyMissingError is the loud refusal: exact try counts, no partial
// enumeration, and the BTCRecover/GPU pointer.
func tooManyMissingError(p PartialSeed) error {
	tries := "over 17 trillion and climbing"
	if len(p.Gaps) == 3 {
		tries = "8,589,934,592"
	}
	return fmt.Errorf("%w: %d missing words in a %d-word phrase = %s checksum tries — "+
		"billions of candidates, beyond offline enumeration. Take the carve to "+
		"BTCRecover (https://github.com/3rdIteration/btcrecover) with GPU tokenlists; "+
		"see docs/WHAT_NEXT.md", ErrTooManyMissing, len(p.Gaps), p.Length, tries)
}

// completeKnownWords answers a gap-free phrase. A checksum-valid phrase is
// returned byte-for-byte as before. A checksum-invalid phrase has no missing
// word, so try the only bounded repair with useful recall: substitute exactly
// one dictionary word at each position.
func completeKnownWords(p PartialSeed, maxResults int) (*SeedCompletion, error) {
	indices := make([]uint16, p.Length)
	for i, w := range p.Words {
		indices[i] = bip39WordIndex[strings.ToLower(w)]
	}
	if !bip39ChecksumValid(indices) {
		return completeOneSubstitution(p, indices, maxResults), nil
	}
	return &SeedCompletion{
		Partial: p,
		Shown:   []Completion{{Words: append([]string(nil), p.Words...)}},
		Total:   1,
	}, nil
}

// substitutionTrial records one checksum-valid, one-word correction without
// carrying a full phrase through the sort. position and word are the stable
// tie-breakers after exact edit distance.
type substitutionTrial struct {
	score    int
	position int
	word     uint16
}

// completeOneSubstitution enumerates every phrase that differs at exactly one
// position. The unchanged token is explicitly excluded; the input is known to
// fail its checksum, but keeping the exclusion structural prevents this helper
// from ever turning into an accidental self-completion path.
func completeOneSubstitution(p PartialSeed, base []uint16, max int) *SeedCompletion {
	indices := append([]uint16(nil), base...)
	trials := make([]substitutionTrial, 0, len(base)*len(bip39Words)/16)
	for position, original := range base {
		for word := range bip39Words {
			candidate := uint16(word)
			if candidate == original {
				continue
			}
			indices[position] = candidate
			if !bip39ChecksumValid(indices) {
				continue
			}
			trials = append(trials, substitutionTrial{
				score:    exactWordDistance(bip39Words[original], bip39Words[candidate]),
				position: position,
				word:     candidate,
			})
		}
		indices[position] = original
	}
	sort.Slice(trials, func(i, j int) bool {
		if trials[i].score != trials[j].score {
			return trials[i].score < trials[j].score
		}
		if trials[i].position != trials[j].position {
			return trials[i].position < trials[j].position
		}
		return trials[i].word < trials[j].word
	})

	res := &SeedCompletion{Partial: p, Total: len(trials)}
	if len(trials) > max {
		trials = trials[:max]
		res.Truncated = true
	}
	for _, trial := range trials {
		phrase := make([]string, len(base))
		for i, idx := range base {
			phrase[i] = bip39Words[idx]
		}
		phrase[trial.position] = bip39Words[trial.word]
		res.Shown = append(res.Shown, Completion{
			Words:     phrase,
			Fill:      []string{bip39Words[trial.word]},
			Positions: []int{trial.position},
			Score:     trial.score,
		})
	}
	return res
}

// exactWordDistance asks the bounded implementation for the exact distance.
// BIP39 words are at most eight ASCII bytes, so a bound equal to the longer
// word cannot trigger its early-out path.
func exactWordDistance(a, b string) int {
	return levenshteinBounded(a, b, max(len(a), len(b)))
}

// cappedDistance is the typo distance capped at 3 (past the scanner's
// typo bound of 2): ordering admits ignorance uniformly beyond it.
func cappedDistance(token, word string) int {
	if d := levenshteinBounded(token, word, bip39TypoDistance); d <= bip39TypoDistance {
		return d
	}
	return bip39TypoDistance + 1
}

// completeOneGap streams one-gap trials in (distance, index) order, so
// Shown is already most-likely first with no sort.
func completeOneGap(res *SeedCompletion, base []uint16, gap int, order []uint16, dist []int, max int) {
	indices := append([]uint16(nil), base...)
	for _, c := range order {
		indices[gap] = c
		if !bip39ChecksumValid(indices) {
			continue
		}
		res.Total++
		if len(res.Shown) >= max {
			continue
		}
		phrase := make([]string, len(base))
		for i, idx := range indices {
			phrase[i] = bip39Words[idx]
		}
		res.Shown = append(res.Shown, Completion{
			Words:     phrase,
			Fill:      []string{bip39Words[c]},
			Positions: []int{gap},
			Score:     dist[c],
		})
	}
	res.Truncated = res.Total > len(res.Shown)
}

// twoGapTrial is a compact valid pair for sorting before materializing:
// 262k trials must not each carry a 24-word slice.
type twoGapTrial struct {
	score int
	i, j  uint16
}

func completeTwoGaps(res *SeedCompletion, base []uint16, gaps []int, orders [][]uint16, dists [][]int, max int) {
	indices := append([]uint16(nil), base...)
	var trials []twoGapTrial
	for _, c0 := range orders[0] {
		indices[gaps[0]] = c0
		for _, c1 := range orders[1] {
			indices[gaps[1]] = c1
			if !bip39ChecksumValid(indices) {
				continue
			}
			trials = append(trials, twoGapTrial{score: dists[0][c0] + dists[1][c1], i: c0, j: c1})
		}
	}
	res.Total = len(trials)
	sort.Slice(trials, func(a, b int) bool {
		if trials[a].score != trials[b].score {
			return trials[a].score < trials[b].score
		}
		if trials[a].i != trials[b].i {
			return trials[a].i < trials[b].i
		}
		return trials[a].j < trials[b].j
	})
	if len(trials) > max {
		trials = trials[:max]
		res.Truncated = true
	}
	for _, t := range trials {
		indices[gaps[0]], indices[gaps[1]] = t.i, t.j
		phrase := make([]string, len(base))
		for i, idx := range indices {
			phrase[i] = bip39Words[idx]
		}
		res.Shown = append(res.Shown, Completion{
			Words:     phrase,
			Fill:      []string{bip39Words[t.i], bip39Words[t.j]},
			Positions: append([]int(nil), gaps...),
			Score:     t.score,
		})
	}
}

// maxSuggestions caps "did you mean" fills per gap: the three most
// likely validating neighbors, not a dump.
const maxSuggestions = 3

// suggestCorrections derives "did you mean" from the shown head
// (most-likely first): per gap, the first distinct fills within typo
// range. Garbage gaps (nothing within range) get no correction.
func suggestCorrections(p PartialSeed, dists [][]int, shown []Completion) []Correction {
	var out []Correction
	for gi, g := range p.Gaps {
		seen := map[string]bool{}
		var suggest []string
		for _, s := range shown {
			w := s.Fill[gi]
			if seen[w] || dists[gi][bip39WordIndex[w]] > bip39TypoDistance {
				continue
			}
			seen[w] = true
			suggest = append(suggest, w)
			if len(suggest) >= maxSuggestions {
				break
			}
		}
		if len(suggest) > 0 {
			out = append(out, Correction{Position: g, Token: p.Words[g], Suggest: suggest})
		}
	}
	return out
}

// SeedAccounts is the watch-only handoff for one candidate phrase: the
// three standard mainnet account keys (BIP44/49/84), each neutering the
// same seed. Three fixed paths is coverage, not path brute force (an
// explicit non-goal): anything exotic stays BTCRecover's job.
type SeedAccounts struct {
	XPub44 string // m/44'/0'/0' as xpub (P2PKH)
	YPub49 string // m/49'/0'/0' as ypub (P2SH-P2WPKH)
	ZPub84 string // m/84'/0'/0' as zpub (P2WPKH)
}

// seedAccountPaths pins the handoff trio: purpose level plus the SLIP132
// account-key version (mirrors xkeyVersions in keys.go).
var seedAccountPaths = []struct {
	purpose uint32
	version uint32
}{
	{44, 0x0488B21E}, // xpub
	{49, 0x049D7CB2}, // ypub
	{84, 0x04B24746}, // zpub
}

// SeedToAccounts derives the watch-only handoff keys for a complete
// checksum-valid mnemonic using the BIP39 empty passphrase. It is the
// compatibility wrapper for SeedToAccountsWithPassphrase.
func SeedToAccounts(mnemonic []string) (*SeedAccounts, error) {
	return SeedToAccountsWithPassphrase(mnemonic, nil)
}

// SeedToAccountsWithPassphrase derives the watch-only handoff keys for a
// complete checksum-valid mnemonic: BIP39 seed → BIP32 master
// → m/purpose'/0'/0' hardened, neutered to account keys. The output
// feeds `findcrypto -watch` with no copy-paste. Invalid phrases refuse;
// the passphrase is UTF-8 NFKD-normalized per BIP39, and private material is
// zeroized before return and never logged. The caller retains ownership of
// passphrase; this function does not mutate it.
func SeedToAccountsWithPassphrase(mnemonic []string, passphrase []byte) (*SeedAccounts, error) {
	seed, err := mnemonicToSeed(mnemonic, passphrase)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(seed)
	mac := hmac.New(sha512.New, []byte("Bitcoin seed"))
	mac.Write(seed)
	master := mac.Sum(nil)
	defer zeroBytes(master)
	masterPriv, masterChain := append([]byte(nil), master[:32]...), append([]byte(nil), master[32:]...)
	defer zeroBytes(masterPriv)
	defer zeroBytes(masterChain)
	if !validPrivBytes(masterPriv) {
		return nil, errors.New("derived an invalid master key (astronomically rare) — retry with the same phrase")
	}
	accts := &SeedAccounts{}
	out := []*string{&accts.XPub44, &accts.YPub49, &accts.ZPub84}
	for i, path := range seedAccountPaths {
		key, err := seedAccountKey(masterPriv, masterChain, path.purpose, path.version)
		if err != nil {
			return nil, err
		}
		*out[i] = key
	}
	return accts, nil
}

// mnemonicToSeed validates the English BIP39 mnemonic and performs the BIP39
// PBKDF2 step. BIP39 requires UTF-8 NFKD for both the mnemonic sentence and
// the optional passphrase. Every mutable normalized/salt buffer is wiped; the
// returned seed belongs to the caller and must also be wiped.
func mnemonicToSeed(mnemonic []string, passphrase []byte) ([]byte, error) {
	sentence, err := seedSentence(mnemonic)
	if err != nil {
		return nil, err
	}
	if !utf8.Valid(passphrase) {
		return nil, errors.New("cannot derive: BIP39 passphrase is not valid UTF-8")
	}
	password := norm.NFKD.Bytes([]byte(sentence))
	defer zeroBytes(password)
	passphraseCopy := append([]byte(nil), passphrase...)
	defer zeroBytes(passphraseCopy)
	// norm.Bytes may return its input unchanged. Normalize a private copy so
	// wiping the result can never mutate the caller's passphrase buffer.
	normalizedPassphrase := norm.NFKD.Bytes(passphraseCopy)
	defer zeroBytes(normalizedPassphrase)
	salt := make([]byte, len("mnemonic")+len(normalizedPassphrase))
	copy(salt, "mnemonic")
	copy(salt[len("mnemonic"):], normalizedPassphrase)
	defer zeroBytes(salt)
	return pbkdf2SHA512(password, salt, 2048, 64), nil
}

// seedSentence validates a complete mnemonic (length, words, checksum)
// and renders the canonical BIP39 sentence (lowercase ASCII — the
// scanner only emits canonical words, so NFKD is a no-op).
func seedSentence(mnemonic []string) (string, error) {
	okLen := false
	for _, l := range bip39Lengths {
		if len(mnemonic) == l {
			okLen = true
			break
		}
	}
	if !okLen {
		return "", fmt.Errorf("cannot derive from %d words: not a seed length (want 12/15/18/21/24)", len(mnemonic))
	}
	lower := make([]string, len(mnemonic))
	indices := make([]uint16, len(mnemonic))
	for i, w := range mnemonic {
		lw := strings.ToLower(w)
		idx, ok := bip39WordIndex[lw]
		if !ok {
			return "", fmt.Errorf("cannot derive: word %d (%q) is not a BIP39 word", i, w)
		}
		lower[i], indices[i] = lw, idx
	}
	if !bip39ChecksumValid(indices) {
		return "", errors.New("cannot derive: the phrase fails the BIP39 checksum")
	}
	return strings.Join(lower, " "), nil
}

// validPrivBytes reports whether 32 bytes are a usable secp256k1 secret
// (nonzero, below the curve order).
func validPrivBytes(b []byte) bool {
	k := new(big.Int).SetBytes(b)
	return k.Sign() != 0 && k.Cmp(secpN) < 0
}

// seedAccountKey derives one m/purpose'/0'/0' account key and serializes
// it with the given SLIP132 version. Fingerprints chain through the
// compressed parent publics per BIP32.
func seedAccountKey(masterPriv, masterChain []byte, purpose, version uint32) (string, error) {
	priv := append([]byte(nil), masterPriv...)
	chain := append([]byte(nil), masterChain...)
	defer zeroBytes(priv)
	defer zeroBytes(chain)
	pub, err := secpSerializeCompressed(secpMul(new(big.Int).SetBytes(priv), secpGenerator()))
	if err != nil {
		return "", err
	}
	fp := hash160(pub)
	var parentFP [4]byte
	for depth, index := range []uint32{purpose | 0x80000000, 0x80000000, 0x80000000} {
		copy(parentFP[:], fp[:4])
		var data [37]byte
		copy(data[1:33], priv)
		binary.BigEndian.PutUint32(data[33:], index)
		mac := hmac.New(sha512.New, chain)
		mac.Write(data[:])
		zeroBytes(data[:])
		I := mac.Sum(nil)
		il := new(big.Int).SetBytes(I[:32])
		if il.Cmp(secpN) >= 0 {
			zeroBytes(I)
			return "", fmt.Errorf("invalid derivation at depth %d (astronomically rare)", depth+1)
		}
		child := new(big.Int).Add(il, new(big.Int).SetBytes(priv))
		child.Mod(child, secpN)
		if child.Sign() == 0 {
			zeroBytes(I)
			return "", fmt.Errorf("invalid derived key at depth %d (astronomically rare)", depth+1)
		}
		childRaw := child.Bytes()
		childPadded := leftPad32(childRaw)
		copy(priv, childPadded)
		zeroBytes(childRaw)
		zeroBytes(childPadded)
		copy(chain, I[32:])
		zeroBytes(I)
		pub, err = secpSerializeCompressed(secpMul(new(big.Int).SetBytes(priv), secpGenerator()))
		if err != nil {
			return "", err
		}
		fp = hash160(pub)
	}
	payload := make([]byte, 78)
	binary.BigEndian.PutUint32(payload[:4], version)
	payload[4] = 3
	copy(payload[5:9], parentFP[:])
	binary.BigEndian.PutUint32(payload[9:13], 0x80000000)
	copy(payload[13:45], chain)
	copy(payload[45:78], pub)
	return base58CheckEncode(payload), nil
}

// leftPad32 renders a big-int byte slice as 32 bytes.
func leftPad32(b []byte) []byte {
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// pbkdf2SHA512 is PBKDF2-HMAC-SHA512 (RFC 2898), dependency-free for the
// BIP39 seed step.
func pbkdf2SHA512(password, salt []byte, iter, keyLen int) []byte {
	out := make([]byte, 0, keyLen)
	for block := 1; len(out) < keyLen; block++ {
		mac := hmac.New(sha512.New, password)
		mac.Write(salt)
		var be [4]byte
		binary.BigEndian.PutUint32(be[:], uint32(block))
		mac.Write(be[:])
		u := mac.Sum(nil)
		acc := append([]byte(nil), u...)
		for i := 1; i < iter; i++ {
			mac = hmac.New(sha512.New, password)
			mac.Write(u)
			nextU := mac.Sum(nil)
			zeroBytes(u)
			u = nextU
			for j := range acc {
				acc[j] ^= u[j]
			}
		}
		out = append(out, acc...)
		zeroBytes(u)
		zeroBytes(acc)
	}
	return out[:keyLen]
}

// zeroBytes best-effort wipes secret buffers. Go offers no locked pages
// here; this still narrows the lifetime of seeds and private keys to
// the deriving call.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// SeedCompleteWarning is the anti-scam box plus the --reveal warning
// pattern that travels with every completion run: local terminal only,
// never transmitted.
func SeedCompleteWarning() string {
	return "WARNING: -complete prints candidate seed phrases to this local terminal only. " +
		"Owner recovery only: keep this output secret, never share, paste, log, or transmit it anywhere — " +
		"candidate phrases are never transmitted off this machine, and anyone who sees one owns that wallet.\n" +
		"SCAM SHIELD: never send your wallet file, keys, seed words, or password guesses to anyone. " +
		"No legitimate tool or person needs them — demands for secrets or upfront payment are the scam. " +
		"Work offline on copies; delete saved output when done. (--reveal rules apply: local eyes only.)"
}
