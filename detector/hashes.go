package detector

import (
	"fmt"
	"sort"
	"strings"
)

// HashScanMaxBytes caps crack-material extraction input; larger buffers skip
// extraction instead of ballooning memory. Carves are ~MBs; whole-file mode
// refuses oversized input before calling.
const HashScanMaxBytes = 256 << 20

// HashSkip is a recognized wallet artifact that produced no cracker-usable
// hash. This includes supported shapes with a complete-enough prefix whose
// remaining bytes fail validation, plus deliberately unsupported formats.
// Very short or structurally damaged artifacts can remain indistinguishable
// from noise and therefore produce no skip.
// (Core mkey patterns stay silent by design: near-misses need 66 exact
// bytes plus method 0 plus sane iterations, and anything looser would
// report noise — see FindMasterKeys.)
type HashSkip struct {
	Offset int64  `json:"offset"`
	Kind   string `json:"kind"` // wallet/artifact format label
	Reason string `json:"reason"`
}

// ExtractHashes finds supported crack-ready password material in data:
// Bitcoin Core mkey records, Ethereum keystores, and Exodus SECO containers.
// baseAbs is the absolute offset of data[0], so hits stay located in the
// scanned bytes. Extraction never emits a hash no supported cracker can use.
// Results sort by offset for stable output.
func ExtractHashes(data []byte, baseAbs int64) []CrackHash {
	hashes, _ := ExtractHashesWithSkips(data, baseAbs)
	return hashes
}

// ExtractHashesWithSkips is ExtractHashes plus the reasons behind its
// rejections: recognized artifacts that failed export validation or are out
// of scope. Skips sort by offset.
func ExtractHashesWithSkips(data []byte, baseAbs int64) ([]CrackHash, []HashSkip) {
	if len(data) > HashScanMaxBytes {
		return nil, nil
	}
	var out []CrackHash
	var skips []HashSkip
	seen := map[string]bool{}
	// Whole files (SQLite pages, BDB duplicates) can hold the same record
	// twice; a cracker gains nothing from the twin, so keep the first.
	emit := func(h CrackHash, err error) {
		if err == nil && !seen[h.Hash] {
			seen[h.Hash] = true
			out = append(out, h)
		}
	}
	for _, m := range FindMasterKeys(data, baseAbs) {
		emit(m.Hash())
	}
	for _, km := range findKeystores(data, baseAbs) {
		raw := data[km.startAbs-baseAbs : km.endAbs-baseAbs]
		p, err := ParseKeystore(raw, km.startAbs)
		if err != nil {
			skips = append(skips, HashSkip{Offset: km.startAbs, Kind: "ethereum-keystore", Reason: skipReason(km.startAbs, err)})
			continue
		}
		h, herr := p.Hash()
		if herr != nil {
			skips = append(skips, HashSkip{Offset: km.startAbs, Kind: "ethereum-keystore", Reason: herr.Error()})
			continue
		}
		emit(h, nil)
	}
	for _, km := range findERC2335Keystores(data, baseAbs) {
		skips = append(skips, HashSkip{
			Offset: km.startAbs,
			Kind:   "erc2335-keystore",
			Reason: "validated ERC-2335 keystore; no supported cracker export",
		})
	}
	for _, m := range findExodusSECO(data, baseAbs) {
		start := m.startAbs - baseAbs
		p, err := parseExodusSECO(data[start:], m.startAbs)
		if err != nil {
			skips = append(skips, HashSkip{Offset: m.startAbs, Kind: "exodus-seco", Reason: err.Error()})
			continue
		}
		emit(p.Hash(), nil)
	}
	skips = append(skips, findPresales(data, baseAbs)...)
	sort.Slice(out, func(i, j int) bool { return out[i].Offset < out[j].Offset })
	sort.Slice(skips, func(i, j int) bool { return skips[i].Offset < skips[j].Offset })
	return out, skips
}

// skipReason strips ParseKeystore's "keystore at byte N: " prefix: the
// skip already carries the offset, so stderr would otherwise name it twice.
func skipReason(offset int64, err error) string {
	msg := err.Error()
	if reason, ok := strings.CutPrefix(msg, fmt.Sprintf("keystore at byte %d: ", offset)); ok {
		return reason
	}
	return msg
}
