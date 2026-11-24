package detector

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
)

// Browser-passworder vault detection. MetaMask is one known consumer, but
// the envelope is not wallet-specific, so a hit is deliberately reported
// under a generic label. A candidate is a JSON object — plain or JSON-escaped
// as in LevelDB storage — carrying sibling data/iv/salt strings with the
// encryptor's exact decoded lengths (iv 16, salt 32 bytes).
//
// Only the label and offsets leave this module; vault ciphertext is
// password-protected secrets.

// browserPassworderMaxSpan bounds the complete JSON object considered for a
// match. Vault data grows with the wallet; objects past this are out of scope.
// It must stay below the block size so the overlap window can hold one object.
const (
	browserPassworderMaxSpan = 2048
	// Invalid, overlapping JSON-looking objects can otherwise make repeated
	// key scans and json.Unmarshal calls consume object-size work per input
	// byte. Real adjacent vaults consume roughly their own byte length, so this
	// shared linear allowance is generous while hostile media stays bounded.
	browserPassworderValidationWorkFactor = 8
)

type browserPassworderMatch struct {
	startAbs, endAbs int64
}

// browserPassworderStarts is a bounded stack/deque of currently open object
// starts. A malformed stream can open an object at every byte and never close
// one; the fixed ring retains only starts that can still form an in-bound
// object, without an input-sized brace index.
type browserPassworderStarts struct {
	values [browserPassworderMaxSpan]int
	head   int
	size   int
}

func (s *browserPassworderStarts) push(value int) {
	if s.size == len(s.values) {
		s.dropFront()
	}
	at := (s.head + s.size) % len(s.values)
	s.values[at] = value
	s.size++
}

func (s *browserPassworderStarts) back() (int, bool) {
	if s.size == 0 {
		return 0, false
	}
	return s.values[(s.head+s.size-1)%len(s.values)], true
}

func (s *browserPassworderStarts) popBack() {
	if s.size > 0 {
		s.size--
	}
}

func (s *browserPassworderStarts) dropFront() {
	if s.size == 0 {
		return
	}
	s.head = (s.head + 1) % len(s.values)
	s.size--
}

func (s *browserPassworderStarts) dropBefore(min int) {
	for s.size > 0 && s.values[s.head] < min {
		s.dropFront()
	}
}

var (
	browserPassworderPlainKeys = [][]byte{
		[]byte(`"data"`), []byte(`"iv"`), []byte(`"salt"`),
	}
	browserPassworderEscapedKeys = [][]byte{
		[]byte(`\"data\"`), []byte(`\"iv\"`), []byte(`\"salt\"`),
	}
)

// findBrowserPassworderVaults visits each bounded, complete object candidate
// once. One streaming lane follows ordinary JSON; the other follows JSON
// object text escaped inside a string. Unmatched braces age out after the
// maximum span, so dense anchors or damaged input stay linear-space and do not
// trigger a backward search per iv occurrence.
func findBrowserPassworderVaults(data []byte, baseAbs int64) []browserPassworderMatch {
	var out []browserPassworderMatch
	var plain, escaped browserPassworderStarts
	validationBudget := int64(len(data)) * browserPassworderValidationWorkFactor
	if validationBudget < browserPassworderMaxSpan {
		validationBudget = browserPassworderMaxSpan
	}
	plainInString := false
	plainEscape := false
	escapedInString := false
	escapedSlashRun := 0

	emitPlain := func(end int) {
		start, ok := plain.back()
		if !ok {
			return
		}
		plain.popBack()
		raw := data[start : end+1]
		if int64(len(raw)) > validationBudget {
			return
		}
		validationBudget -= int64(len(raw))
		if hasAllBrowserPassworderKeys(raw, browserPassworderPlainKeys) && validBrowserPassworderJSON(raw) {
			out = append(out, browserPassworderMatch{baseAbs + int64(start), baseAbs + int64(end+1)})
		}
	}
	emitEscaped := func(end int) {
		start, ok := escaped.back()
		if !ok {
			return
		}
		escaped.popBack()
		raw := data[start : end+1]
		if int64(len(raw)) > validationBudget {
			return
		}
		validationBudget -= int64(len(raw))
		if hasAllBrowserPassworderKeys(raw, browserPassworderEscapedKeys) && validEscapedBrowserPassworderJSON(raw) {
			out = append(out, browserPassworderMatch{baseAbs + int64(start), baseAbs + int64(end+1)})
		}
	}

	for i, c := range data {
		// At byte i, a start below this point would make an inclusive object
		// longer than browserPassworderMaxSpan.
		minStart := i - browserPassworderMaxSpan + 1
		plain.dropBefore(minStart)
		escaped.dropBefore(minStart)
		if plain.size == 0 {
			plainInString = false
			plainEscape = false
		}
		if escaped.size == 0 {
			escapedInString = false
			escapedSlashRun = 0
		}

		// Ordinary JSON lane. Quotes before the first open object are noise,
		// so a damaged prefix cannot leave the scanner permanently in-string.
		if plain.size == 0 {
			if c == '{' {
				plain.push(i)
			}
		} else if plainInString {
			if plainEscape {
				plainEscape = false
			} else if c == '\\' {
				plainEscape = true
			} else if c == '"' {
				plainInString = false
			}
		} else {
			switch c {
			case '"':
				plainInString = true
			case '{':
				plain.push(i)
			case '}':
				emitPlain(i)
			}
		}

		// Escaped-JSON lane. After one outer JSON-string decode, a quote is
		// structural when its raw backslash run is 1 mod 4; a 3-mod-4 run
		// represents a quote escaped inside an inner JSON string.
		if escaped.size == 0 {
			if c == '{' && looksLikeEscapedJSONObject(data, i) {
				escaped.push(i)
			}
			escapedSlashRun = 0
			continue
		}
		if c == '\\' {
			escapedSlashRun++
			continue
		}
		if c == '"' && escapedSlashRun%4 == 1 {
			escapedInString = !escapedInString
		}
		escapedSlashRun = 0
		if escapedInString {
			continue
		}
		switch c {
		case '{':
			escaped.push(i)
		case '}':
			emitEscaped(i)
		}
	}
	return out
}

func looksLikeEscapedJSONObject(data []byte, start int) bool {
	for at := start + 1; at < len(data) && at-start < browserPassworderMaxSpan; at++ {
		switch data[at] {
		case ' ', '\t', '\r', '\n':
			continue
		case '\\':
			return at+1 < len(data) && data[at+1] == '"'
		default:
			return false
		}
	}
	return false
}

func hasAllBrowserPassworderKeys(raw []byte, keys [][]byte) bool {
	for _, key := range keys {
		if !bytes.Contains(raw, key) {
			return false
		}
	}
	return true
}

func validBrowserPassworderJSON(raw []byte) bool {
	var object map[string]any
	return json.Unmarshal(raw, &object) == nil && validBrowserPassworderEnvelope(object)
}

func validEscapedBrowserPassworderJSON(raw []byte) bool {
	quoted := make([]byte, 0, len(raw)+2)
	quoted = append(quoted, '"')
	quoted = append(quoted, raw...)
	quoted = append(quoted, '"')
	var decoded string
	if json.Unmarshal(quoted, &decoded) != nil {
		return false
	}
	return validBrowserPassworderJSON([]byte(decoded))
}

func validBrowserPassworderEnvelope(object map[string]any) bool {
	dataText, dataOK := object["data"].(string)
	ivText, ivOK := object["iv"].(string)
	saltText, saltOK := object["salt"].(string)
	if !dataOK || !ivOK || !saltOK {
		return false
	}
	data, err := base64.StdEncoding.DecodeString(dataText)
	if err != nil || len(data) < 16 {
		return false
	}
	iv, err := base64.StdEncoding.DecodeString(ivText)
	if err != nil || len(iv) != 16 {
		return false
	}
	salt, err := base64.StdEncoding.DecodeString(saltText)
	return err == nil && len(salt) == 32
}
