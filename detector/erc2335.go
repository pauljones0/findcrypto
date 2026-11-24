package detector

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ERC-2335 BLS12-381 keystores are modular v4 JSON objects. The 3 KiB
// bound covers the official scrypt/PBKDF2 vectors while keeping block overlap
// bounded below the scanner's block size.
const (
	erc2335MaxSpan = 3072
	// Invalid, overlapping JSON-looking objects can otherwise make repeated
	// json.Unmarshal calls consume object-size work per input byte. Real
	// adjacent keystores consume roughly their own byte length, so this linear
	// allowance is generous while hostile media remains bounded.
	erc2335ValidationWorkFactor = 8
)

var erc2335Anchor = []byte(`"checksum"`)

type erc2335Match struct {
	startAbs, endAbs int64
}

type erc2335Module struct {
	Function string          `json:"function"`
	Params   json.RawMessage `json:"params"`
	Message  *string         `json:"message"`
}

type erc2335Crypto struct {
	KDF      *erc2335Module `json:"kdf"`
	Checksum *erc2335Module `json:"checksum"`
	Cipher   *erc2335Module `json:"cipher"`
}

type erc2335File struct {
	Crypto  *erc2335Crypto `json:"crypto"`
	Pubkey  string         `json:"pubkey"`
	Path    *string        `json:"path"`
	UUID    string         `json:"uuid"`
	Version int            `json:"version"`
}

type erc2335Params struct {
	DKLen int    `json:"dklen"`
	N     int    `json:"n"`
	R     int    `json:"r"`
	P     int    `json:"p"`
	C     int    `json:"c"`
	PRF   string `json:"prf"`
	Salt  string `json:"salt"`
	IV    string `json:"iv"`
}

func findERC2335Keystores(data []byte, baseAbs int64) []erc2335Match {
	if !bytes.Contains(data, erc2335Anchor) {
		return nil
	}
	var out []erc2335Match
	validationBudget := int64(len(data)) * erc2335ValidationWorkFactor
	if validationBudget < erc2335MaxSpan {
		validationBudget = erc2335MaxSpan
	}

	// Find the next anchor incrementally and remember only the latest one. The
	// two brace stacks retain at most the 3 KiB candidate window, so even
	// HashScanMaxBytes of brace-dense input cannot cause an auxiliary-memory
	// spike. Quote parity is relative: an unmatched quote in unrelated raw
	// bytes cannot poison matching for a later opening brace.
	lastAnchor := -1
	nextAnchor := bytes.Index(data, erc2335Anchor)
	var stacks [2]erc2335BraceStack
	quoteParity := 0
	backslashes := 0
	for pos, b := range data {
		if pos == nextAnchor {
			lastAnchor = pos
			nextFrom := pos + len(erc2335Anchor)
			nextAnchor = -1
			if nextFrom+len(erc2335Anchor) <= len(data) {
				if rel := bytes.Index(data[nextFrom:], erc2335Anchor); rel >= 0 {
					nextAnchor = nextFrom + rel
				}
			}
		}

		minStart := pos + 1 - erc2335MaxSpan
		switch b {
		case '"':
			if backslashes%2 == 0 {
				quoteParity ^= 1
			}
		case '{':
			stacks[quoteParity].push(pos, minStart)
		case '}':
			start, ok := stacks[quoteParity].pop(minStart)
			if !ok || lastAnchor < start || lastAnchor+len(erc2335Anchor) > pos+1 {
				break
			}
			end := pos + 1
			if !erc2335RootCandidate(data, start, end) {
				break
			}
			span := end - start
			if int64(span) > validationBudget {
				break
			}
			validationBudget -= int64(span)
			if validateERC2335(data[start:end]) == nil {
				out = append(out, erc2335Match{baseAbs + int64(start), baseAbs + int64(end)})
			}
		}
		if b == '\\' {
			backslashes++
		} else {
			backslashes = 0
		}
	}
	return out
}

type erc2335BraceStack struct {
	values []int
	head   int
}

func (s *erc2335BraceStack) prune(minStart int) {
	for s.head < len(s.values) && s.values[s.head] < minStart {
		s.head++
	}
	if s.head == len(s.values) {
		s.values = s.values[:0]
		s.head = 0
	} else if s.head >= erc2335MaxSpan && s.head*2 >= len(s.values) {
		copy(s.values, s.values[s.head:])
		s.values = s.values[:len(s.values)-s.head]
		s.head = 0
	}
}

func (s *erc2335BraceStack) push(pos, minStart int) {
	s.prune(minStart)
	s.values = append(s.values, pos)
}

func (s *erc2335BraceStack) pop(minStart int) (int, bool) {
	s.prune(minStart)
	if len(s.values) == 0 {
		return 0, false
	}
	last := len(s.values) - 1
	pos := s.values[last]
	s.values = s.values[:last]
	if len(s.values) == s.head {
		s.values = s.values[:0]
		s.head = 0
	}
	return pos, true
}

func erc2335RootCandidate(data []byte, start, end int) bool {
	i := start + 1
	// The standard root keys may be reordered, but a normal file never needs
	// kilobytes of whitespace before its first key. Bounding this prefix keeps
	// malformed nested objects from becoming another variable-work surface.
	limit := i + 256
	if limit > end {
		limit = end
	}
	for i < limit {
		switch data[i] {
		case ' ', '\t', '\r', '\n':
			i++
			continue
		}
		break
	}
	if i == limit {
		return false
	}
	for _, key := range []string{`"crypto"`, `"description"`, `"pubkey"`, `"path"`, `"uuid"`, `"version"`} {
		if !bytes.HasPrefix(data[i:end], []byte(key)) {
			continue
		}
		j := i + len(key)
		for j < end {
			switch data[j] {
			case ' ', '\t', '\r', '\n':
				j++
				continue
			}
			break
		}
		return j < end && data[j] == ':'
	}
	return false
}

func validateERC2335(raw []byte) error {
	var ks erc2335File
	if err := json.Unmarshal(raw, &ks); err != nil {
		return fmt.Errorf("not valid JSON: %w", err)
	}
	if ks.Version != 4 {
		return fmt.Errorf("version is %d, want 4", ks.Version)
	}
	if ks.Path == nil || !validERC2334Path(*ks.Path) {
		return errors.New("path must be empty or a valid ERC-2334 m/12381/... path")
	}
	if !validUUIDShape(ks.UUID) {
		return errors.New("uuid is not a random RFC-4122 UUIDv4")
	}
	if ks.Pubkey != "" && (len(ks.Pubkey) != 96 || !isHex(ks.Pubkey)) {
		return errors.New("pubkey is not 48-byte hex")
	}
	if ks.Crypto == nil || ks.Crypto.KDF == nil || ks.Crypto.Checksum == nil || ks.Crypto.Cipher == nil {
		return errors.New("crypto kdf/checksum/cipher modules are required")
	}
	for name, module := range map[string]*erc2335Module{
		"kdf": ks.Crypto.KDF, "checksum": ks.Crypto.Checksum, "cipher": ks.Crypto.Cipher,
	} {
		if module.Function == "" || module.Message == nil || len(module.Params) == 0 {
			return fmt.Errorf("%s module lacks function, params, or message", name)
		}
		var object map[string]json.RawMessage
		if err := json.Unmarshal(module.Params, &object); err != nil || object == nil {
			return fmt.Errorf("%s params are not an object", name)
		}
	}
	if *ks.Crypto.KDF.Message != "" {
		return errors.New("kdf message must be empty")
	}
	var kdf erc2335Params
	if err := json.Unmarshal(ks.Crypto.KDF.Params, &kdf); err != nil {
		return errors.New("kdf params are not an object")
	}
	if kdf.DKLen != 32 || len(kdf.Salt) != 64 || !isHex(kdf.Salt) {
		return errors.New("kdf needs dklen 32 and a 32-byte hex salt")
	}
	switch ks.Crypto.KDF.Function {
	case "scrypt":
		if kdf.N < 2 || kdf.N&(kdf.N-1) != 0 || kdf.N > 1<<30 || kdf.R < 1 || kdf.R > 1<<20 || kdf.P < 1 || kdf.P > 1<<20 {
			return errors.New("scrypt needs bounded power-of-two n and positive r/p")
		}
	case "pbkdf2":
		if kdf.C < 1 || kdf.PRF != "hmac-sha256" {
			return errors.New("pbkdf2 needs positive c and hmac-sha256")
		}
	default:
		return fmt.Errorf("unsupported kdf %q", ks.Crypto.KDF.Function)
	}
	if ks.Crypto.Checksum.Function != "sha256" || len(*ks.Crypto.Checksum.Message) != 64 || !isHex(*ks.Crypto.Checksum.Message) {
		return errors.New("checksum must be sha256 with a 32-byte hex message")
	}
	var checksumParams map[string]json.RawMessage
	if err := json.Unmarshal(ks.Crypto.Checksum.Params, &checksumParams); err != nil || len(checksumParams) != 0 {
		return errors.New("sha256 checksum params must be an empty object")
	}
	var cipher erc2335Params
	if err := json.Unmarshal(ks.Crypto.Cipher.Params, &cipher); err != nil {
		return errors.New("cipher params are not an object")
	}
	if ks.Crypto.Cipher.Function != "aes-128-ctr" || len(cipher.IV) != 32 || !isHex(cipher.IV) || !isHex(*ks.Crypto.Cipher.Message) {
		return errors.New("cipher must be aes-128-ctr with a 16-byte hex iv and hex message")
	}
	return nil
}

func validERC2334Path(path string) bool {
	if path == "" {
		return true
	}
	parts := strings.Split(path, "/")
	if len(parts) < 5 || parts[0] != "m" || parts[1] != "12381" {
		return false
	}
	for _, part := range parts[1:] {
		if part == "" {
			return false
		}
		for i := 0; i < len(part); i++ {
			if part[i] < '0' || part[i] > '9' {
				return false
			}
		}
		if _, err := strconv.ParseUint(part, 10, 32); err != nil {
			return false
		}
	}
	return true
}

func validUUIDShape(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if s[i] != '-' {
				return false
			}
			continue
		}
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return s[14] == '4' && strings.ContainsRune("89aAbB", rune(s[19]))
}
