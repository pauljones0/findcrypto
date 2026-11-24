package detector

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func exodusFixture(blobSize int) []byte {
	header := make([]byte, exodusHeaderSize)
	copy(header, "SECO")
	pos := 12
	putField := func(value string) {
		header[pos] = byte(len(value))
		pos++
		copy(header[pos:], value)
		pos += len(value)
	}
	putField(string(exodusVersionTag))
	putField("Exodus")
	putField("26.11.0")

	meta := make([]byte, exodusMetadataSize)
	for i := 0; i < 32; i++ {
		meta[i] = byte(i)
		meta[104+i] = byte(0xc0 + i)
	}
	binary.BigEndian.PutUint32(meta[32:36], 16384)
	binary.BigEndian.PutUint32(meta[36:40], 8)
	binary.BigEndian.PutUint32(meta[40:44], 1)
	copy(meta[44:76], "aes-256-gcm")
	for i := 0; i < 12; i++ {
		meta[76+i] = byte(0xa0 + i)
		meta[136+i] = byte(0xe0 + i)
	}
	for i := 0; i < 16; i++ {
		meta[88+i] = byte(0xb0 + i)
		meta[148+i] = byte(0xf0 + i)
	}
	blob := make([]byte, blobSize)
	for i := range blob {
		blob[i] = byte(i*29 + 7)
	}
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(blob)))
	checkInput := append(append(bytes.Clone(meta), length...), blob...)
	checksum := sha256.Sum256(checkInput)
	out := append(bytes.Clone(header), checksum[:]...)
	out = append(out, meta...)
	out = append(out, length...)
	return append(out, blob...)
}

func TestExodusSECOHashcatExport(t *testing.T) {
	raw := exodusFixture(96)
	p, err := parseExodusSECO(raw, 700)
	if err != nil {
		t.Fatal(err)
	}
	h := p.Hash()
	want := strings.Join([]string{
		"EXODUS", "16384", "8", "1",
		base64.StdEncoding.EncodeToString(raw[256:288]),
		base64.StdEncoding.EncodeToString(raw[332:344]),
		base64.StdEncoding.EncodeToString(raw[360:392]),
		base64.StdEncoding.EncodeToString(raw[344:360]),
	}, ":")
	if h.Hash != want || h.Format != "exodus-seco" || h.KDF != "scrypt" || h.Offset != 700 {
		t.Fatalf("hash = %+v\nwant %s", h, want)
	}
	hashes, skips := ExtractHashesWithSkips(append([]byte("pad"), raw...), 100)
	if len(skips) != 0 || len(hashes) != 1 || hashes[0].Offset != 103 || hashes[0].Hash != want {
		t.Fatalf("hashes=%+v skips=%+v", hashes, skips)
	}
}

func TestExodusCorpusMatchesOfficialExtractor(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "password-handoff", "seed.seco"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := parseExodusSECO(raw, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Pinned from hashcat's official tools/exodus2hashcat.py against the
	// committed deterministic corpus fixture. This is an independent oracle,
	// not a re-rendering of fields with the implementation under test.
	const want = "EXODUS:16384:8:1:WygYxpLfUfKvr1ve65VnNjiy02zMaWOiXvXCSY80r1Q=:c1hu4HZHsqV436FZ:4kuaAo2B9edjQiEpOeqx7iNa1poMoxVMfOZbFb263fI=:jhd8r9vxjpiRlXEslbj4wg=="
	if got := p.Hash().Hash; got != want {
		t.Fatalf("hash = %q\nwant = %q", got, want)
	}
}

func TestExodusSECOStrictMutations(t *testing.T) {
	base := exodusFixture(64)
	mutants := map[string]func([]byte){
		"version":          func(b []byte) { b[7] = 1 },
		"reserved":         func(b []byte) { b[11] = 1 },
		"tag":              func(b []byte) { b[13] ^= 1 },
		"app":              func(b []byte) { b[33] ^= 1 },
		"header-padding":   func(b []byte) { b[223] = 1 },
		"cipher":           func(b []byte) { b[300] ^= 1 },
		"metadata-padding": func(b []byte) { b[511] = 1 },
		"non-power-n":      func(b []byte) { binary.BigEndian.PutUint32(b[288:292], 3) },
		"empty-blob":       func(b []byte) { binary.BigEndian.PutUint32(b[512:516], 0) },
	}
	for name, mutate := range mutants {
		t.Run(name, func(t *testing.T) {
			raw := bytes.Clone(base)
			mutate(raw)
			if got := findExodusSECO(raw, 0); len(got) != 0 {
				t.Fatalf("structural mutant detected: %+v", got)
			}
			if _, err := parseExodusSECO(raw, 0); err == nil {
				t.Fatal("structural mutant parsed")
			}
		})
	}
	if _, err := parseExodusSECO(base[:515], 0); err == nil {
		t.Fatal("truncated prefix parsed")
	}
	if _, err := parseExodusSECO(base[:len(base)-1], 0); err == nil || !strings.Contains(err.Error(), "truncated encrypted blob") {
		t.Fatalf("truncated blob error = %v", err)
	}
	badChecksum := bytes.Clone(base)
	badChecksum[224] ^= 1
	if got := findExodusSECO(badChecksum, 0); len(got) != 1 {
		t.Fatalf("recoverable checksum-damaged prefix should still detect, got %+v", got)
	}
	hashes, skips := ExtractHashesWithSkips(badChecksum, 40)
	if len(hashes) != 0 || len(skips) != 1 || skips[0].Kind != "exodus-seco" || !strings.Contains(skips[0].Reason, "checksum") {
		t.Fatalf("checksum damage hashes=%+v skips=%+v", hashes, skips)
	}
}

func TestExodusFutureScryptParamDetectsButDoesNotExport(t *testing.T) {
	raw := exodusFixture(64)
	binary.BigEndian.PutUint32(raw[288:292], 1048576)
	checksum := sha256.Sum256(raw[256:])
	copy(raw[224:256], checksum[:])
	if got := findExodusSECO(raw, 0); len(got) != 1 {
		t.Fatalf("structurally valid future container should remain discoverable: %+v", got)
	}
	if _, err := parseExodusSECO(raw, 0); err == nil || !strings.Contains(err.Error(), "Hashcat mode 28200") {
		t.Fatalf("future parameter export error = %v", err)
	}
	hashes, skips := ExtractHashesWithSkips(raw, 0)
	if len(hashes) != 0 || len(skips) != 1 || !strings.Contains(skips[0].Reason, "six-digit") {
		t.Fatalf("future params hashes=%+v skips=%+v", hashes, skips)
	}
}

func TestScanExodusSECOAcrossBoundaryOnce(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "image.bin")
	start := 3900
	raw := append(bytes.Repeat([]byte{0x55}, start), exodusFixture(80)...)
	raw = append(raw, bytes.Repeat([]byte{0x33}, 5000)...)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	var hits []Detection
	if err := ScanWithOptions(0, path, Options{}, func(d Detection) {
		if d.Needle == "exodus-seco" {
			hits = append(hits, d)
		}
	}, func(ProgressInfo) {}); err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Offset != int64(start) || hits[0].MatchLen != exodusPrefixSpan {
		t.Fatalf("hits = %+v", hits)
	}
}

func TestExodusSECONoiseSilent(t *testing.T) {
	for _, raw := range [][]byte{
		[]byte("SECO is a container format"),
		bytes.Repeat([]byte("SECO"), 1000),
		append(bytes.Repeat([]byte{0}, 600), []byte("seco-v0-scrypt-aes Exodus aes-256-gcm")...),
	} {
		if got := findExodusSECO(raw, 0); len(got) != 0 {
			t.Fatalf("noise produced %+v", got)
		}
	}
}
