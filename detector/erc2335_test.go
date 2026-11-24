package detector

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Official ERC-2335 scrypt vector, with whitespace compacted only.
const erc2335ScryptVector = `{"crypto":{"kdf":{"function":"scrypt","params":{"dklen":32,"n":262144,"p":1,"r":8,"salt":"d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"},"message":""},"checksum":{"function":"sha256","params":{},"message":"d2217fe5f3e9a1e34581ef8a78f7c9928e436d36dacc5e846690a5581e8ea484"},"cipher":{"function":"aes-128-ctr","params":{"iv":"264daa3f303d7259501c93d997d84fe6"},"message":"06ae90d55fe0a6e9c5c3bc5b170827b2e5cce3929ed3f116c2811e6366dfe20f"}},"description":"test","pubkey":"9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07","path":"m/12381/60/3141592653/589793238","uuid":"1d85ae20-35c5-4611-98e8-aa14a633906f","version":4}`

func TestERC2335OfficialVector(t *testing.T) {
	if err := validateERC2335([]byte(erc2335ScryptVector)); err != nil {
		t.Fatal(err)
	}
	raw := []byte("prefix " + erc2335ScryptVector + " suffix")
	matches := findERC2335Keystores(raw, 900)
	if len(matches) != 1 {
		t.Fatalf("matches = %+v", matches)
	}
	if matches[0].startAbs != 907 || matches[0].endAbs-matches[0].startAbs != int64(len(erc2335ScryptVector)) {
		t.Fatalf("match bounds = %+v", matches[0])
	}
	_, skips := ExtractHashesWithSkips(raw, 900)
	found := false
	for _, skip := range skips {
		if skip.Kind == "erc2335-keystore" && strings.Contains(skip.Reason, "no supported cracker export") {
			found = true
		}
	}
	if !found {
		t.Fatalf("ERC-2335 skip missing: %+v", skips)
	}
}

func TestERC2335StrictMutations(t *testing.T) {
	mutants := map[string]string{
		"version":      strings.Replace(erc2335ScryptVector, `"version":4`, `"version":3`, 1),
		"uuid":         strings.Replace(erc2335ScryptVector, `1d85ae20-35c5-4611-98e8-aa14a633906f`, `not-a-uuid`, 1),
		"cipher":       strings.Replace(erc2335ScryptVector, `aes-128-ctr`, `aes-256-cbc`, 1),
		"checksum":     strings.Replace(erc2335ScryptVector, `"function":"sha256"`, `"function":"keccak256"`, 1),
		"pubkey":       strings.Replace(erc2335ScryptVector, `9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07`, `00`, 1),
		"path":         strings.Replace(erc2335ScryptVector, `m/12381/60/3141592653/589793238`, `not/an/erc2334/path`, 1),
		"uuid-version": strings.Replace(erc2335ScryptVector, `1d85ae20-35c5-4611-98e8-aa14a633906f`, `1d85ae20-35c5-1611-18e8-aa14a633906f`, 1),
		"n":            strings.Replace(erc2335ScryptVector, `"n":262144`, `"n":3`, 1),
		"kdf-message":  strings.Replace(erc2335ScryptVector, `"message":""`, `"message":"00"`, 1),
		"null-params":  strings.Replace(erc2335ScryptVector, `"params":{}`, `"params":  null `, 1),
	}
	for name, raw := range mutants {
		t.Run(name, func(t *testing.T) {
			if err := validateERC2335([]byte(raw)); err == nil {
				t.Fatal("mutant accepted")
			}
			if got := findERC2335Keystores([]byte(raw), 0); len(got) != 0 {
				t.Fatalf("mutant detected: %+v", got)
			}
		})
	}
}

func TestERC2335EmptyUnknownPath(t *testing.T) {
	raw := strings.Replace(erc2335ScryptVector, `m/12381/60/3141592653/589793238`, ``, 1)
	if err := validateERC2335([]byte(raw)); err != nil {
		t.Fatalf("empty unknown path is permitted by ERC-2335: %v", err)
	}
}

func TestERC2335PBKDF2AndNoise(t *testing.T) {
	pbkdf2 := strings.Replace(erc2335ScryptVector,
		`"function":"scrypt","params":{"dklen":32,"n":262144,"p":1,"r":8,"salt":`,
		`"function":"pbkdf2","params":{"dklen":32,"c":262144,"prf":"hmac-sha256","salt":`, 1)
	if err := validateERC2335([]byte(pbkdf2)); err != nil {
		t.Fatal(err)
	}
	if got := findERC2335Keystores([]byte(strings.Repeat(`{"checksum":"words"}`, 100)), 0); len(got) != 0 {
		t.Fatalf("prose-shaped JSON produced %d matches", len(got))
	}
}

func TestERC2335DenseAnchorsStayLinear(t *testing.T) {
	for _, token := range []string{`"checksum"`, `{"checksum"`, `{"crypto":"checksum"`} {
		// Repeated anchors used to re-walk a 3 KiB look-behind. Nearby unmatched
		// opening braces were worse: every anchor retried 32 separate 8 KiB
		// forward scans. Four MiB exercises both hostile shapes while the
		// bounded streaming matcher keeps time and memory linear.
		raw := bytes.Repeat([]byte(token), 4<<20/len(token))
		started := time.Now()
		if got := findERC2335Keystores(raw, 0); len(got) != 0 {
			t.Fatalf("dense %q prose produced %d matches", token, len(got))
		}
		if elapsed := time.Since(started); elapsed > 2*time.Second {
			t.Fatalf("dense %q scan took %s; expected a linear pass", token, elapsed)
		}
	}
}

func TestScanERC2335AcrossBoundaryOnce(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "validator.img")
	start := 3900
	raw := append(bytes.Repeat([]byte{0x51}, start), []byte(erc2335ScryptVector)...)
	raw = append(raw, bytes.Repeat([]byte{0x29}, 5000)...)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	var hits []Detection
	if err := ScanWithOptions(0, path, Options{}, func(d Detection) {
		if d.Needle == "erc2335-keystore" {
			hits = append(hits, d)
		}
	}, func(ProgressInfo) {}); err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Offset != int64(start) || hits[0].MatchLen != len(erc2335ScryptVector) {
		t.Fatalf("hits = %+v", hits)
	}
}
