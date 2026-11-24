package detector

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Exodus Desktop stores its encrypted seed in a secure-container (SECO)
// file. The fixed 516-byte prefix is enough to identify an Exodus v0
// container on raw media; crack-material export additionally requires the
// complete declared blob and its checksum.
const (
	exodusHeaderSize   = 224
	exodusChecksumSize = 32
	exodusMetadataSize = 256
	exodusPrefixSpan   = exodusHeaderSize + exodusChecksumSize + exodusMetadataSize + 4
	// Hashcat mode 28200 currently accepts at most six decimal digits for
	// each scrypt parameter. Never promise a crack-ready line it will reject.
	exodusMaxScryptParam = 999999
)

var (
	exodusMagic      = []byte("SECO")
	exodusVersionTag = []byte("seco-v0-scrypt-aes")
)

type exodusMatch struct {
	startAbs, endAbs int64
}

type exodusParams struct {
	Salt, BlobKeyIV, BlobKey, BlobKeyAuthTag []byte
	N, R, P                                  uint32
	Offset, EndAbs                           int64
}

// findExodusSECO finds structurally complete fixed prefixes. It intentionally
// does not require the variable-sized blob to fit in a scan block: exact
// header, application attribution, cipher, padding, and sane scrypt
// metadata already make this a high-confidence forensic signature. The full
// checksum is mandatory later in parseExodusSECO before any hash is exported.
func findExodusSECO(data []byte, baseAbs int64) []exodusMatch {
	var out []exodusMatch
	for at := 0; at+len(exodusMagic) <= len(data); {
		rel := bytes.Index(data[at:], exodusMagic)
		if rel < 0 {
			break
		}
		start := at + rel
		if start+exodusPrefixSpan <= len(data) {
			if _, err := parseExodusPrefix(data[start : start+exodusPrefixSpan]); err == nil {
				out = append(out, exodusMatch{
					startAbs: baseAbs + int64(start),
					endAbs:   baseAbs + int64(start+exodusPrefixSpan),
				})
			}
		}
		at = start + 1
	}
	return out
}

func parseExodusPrefix(raw []byte) (exodusParams, error) {
	if len(raw) < exodusPrefixSpan {
		return exodusParams{}, fmt.Errorf("truncated fixed prefix: got %d bytes, need %d", len(raw), exodusPrefixSpan)
	}
	if !bytes.Equal(raw[:4], exodusMagic) {
		return exodusParams{}, errors.New("not a SECO container")
	}
	if binary.BigEndian.Uint32(raw[4:8]) != 0 {
		return exodusParams{}, errors.New("unsupported SECO version")
	}
	if binary.BigEndian.Uint32(raw[8:12]) != 0 {
		return exodusParams{}, errors.New("nonzero reserved header bytes")
	}

	pos := 12
	field := func(name string) ([]byte, error) {
		if pos >= exodusHeaderSize {
			return nil, fmt.Errorf("missing %s length", name)
		}
		n := int(raw[pos])
		pos++
		if pos+n > exodusHeaderSize {
			return nil, fmt.Errorf("%s exceeds fixed header", name)
		}
		value := raw[pos : pos+n]
		pos += n
		return value, nil
	}
	tag, err := field("version tag")
	if err != nil {
		return exodusParams{}, err
	}
	app, err := field("application name")
	if err != nil {
		return exodusParams{}, err
	}
	appVersion, err := field("application version")
	if err != nil {
		return exodusParams{}, err
	}
	if !bytes.Equal(tag, exodusVersionTag) {
		return exodusParams{}, errors.New("unsupported SECO version tag")
	}
	if !utf8.Valid(app) || !strings.EqualFold(string(app), "Exodus") {
		return exodusParams{}, errors.New("SECO application is not Exodus")
	}
	if len(appVersion) == 0 || !utf8.Valid(appVersion) {
		return exodusParams{}, errors.New("application version is empty or not UTF-8")
	}
	if !allZero(raw[pos:exodusHeaderSize]) {
		return exodusParams{}, errors.New("nonzero fixed-header padding")
	}

	meta := raw[exodusHeaderSize+exodusChecksumSize : exodusHeaderSize+exodusChecksumSize+exodusMetadataSize]
	n := binary.BigEndian.Uint32(meta[32:36])
	r := binary.BigEndian.Uint32(meta[36:40])
	p := binary.BigEndian.Uint32(meta[40:44])
	if n < 2 || n&(n-1) != 0 || r < 1 || p < 1 {
		return exodusParams{}, fmt.Errorf("unsupported scrypt parameters n/r/p=%d/%d/%d", n, r, p)
	}
	cipher := meta[44:76]
	zero := bytes.IndexByte(cipher, 0)
	if zero < 0 || string(cipher[:zero]) != "aes-256-gcm" || !allZero(cipher[zero:]) {
		return exodusParams{}, errors.New("metadata cipher is not zero-padded aes-256-gcm")
	}
	if !allZero(meta[164:]) {
		return exodusParams{}, errors.New("nonzero metadata padding")
	}
	if binary.BigEndian.Uint32(raw[512:516]) == 0 {
		return exodusParams{}, errors.New("empty encrypted blob")
	}
	return exodusParams{
		Salt:           bytes.Clone(meta[0:32]),
		BlobKeyIV:      bytes.Clone(meta[76:88]),
		BlobKeyAuthTag: bytes.Clone(meta[88:104]),
		BlobKey:        bytes.Clone(meta[104:136]),
		N:              n, R: r, P: p,
	}, nil
}

func parseExodusSECO(raw []byte, offset int64) (exodusParams, error) {
	p, err := parseExodusPrefix(raw)
	if err != nil {
		return exodusParams{}, err
	}
	blobLen := uint64(binary.BigEndian.Uint32(raw[512:516]))
	total := uint64(exodusPrefixSpan) + blobLen
	if total > uint64(len(raw)) {
		return exodusParams{}, fmt.Errorf("truncated encrypted blob: declares %d bytes, only %d remain", blobLen, len(raw)-exodusPrefixSpan)
	}
	want := raw[exodusHeaderSize : exodusHeaderSize+exodusChecksumSize]
	checksumInput := raw[exodusHeaderSize+exodusChecksumSize : int(total)]
	got := sha256.Sum256(checksumInput)
	if !bytes.Equal(want, got[:]) {
		return exodusParams{}, errors.New("SECO checksum mismatch")
	}
	if p.N > exodusMaxScryptParam || p.R > exodusMaxScryptParam || p.P > exodusMaxScryptParam {
		return exodusParams{}, fmt.Errorf("scrypt parameters n/r/p=%d/%d/%d exceed Hashcat mode 28200's six-digit fields", p.N, p.R, p.P)
	}
	p.Offset = offset
	p.EndAbs = offset + int64(total)
	return p, nil
}

func (p exodusParams) Hash() CrackHash {
	return CrackHash{
		Format: "exodus-seco",
		Hash: fmt.Sprintf("EXODUS:%d:%d:%d:%s:%s:%s:%s",
			p.N, p.R, p.P,
			base64.StdEncoding.EncodeToString(p.Salt),
			base64.StdEncoding.EncodeToString(p.BlobKeyIV),
			base64.StdEncoding.EncodeToString(p.BlobKey),
			base64.StdEncoding.EncodeToString(p.BlobKeyAuthTag)),
		KDF:        "scrypt",
		Iterations: p.N,
		SaltHex:    hex.EncodeToString(p.Salt),
		Params: map[string]string{
			"n": fmt.Sprint(p.N), "r": fmt.Sprint(p.R), "p": fmt.Sprint(p.P),
			"cipher": "aes-256-gcm", "hashcat_mode": "28200",
		},
		Offset: p.Offset,
	}
}

func allZero(raw []byte) bool {
	for _, b := range raw {
		if b != 0 {
			return false
		}
	}
	return true
}
