package detector

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// RFC 8032 test vector 1 supplies an implementation-independent Ed25519
// seed/public-key pair. Solana CLI keypair files serialize the same
// seed||public-key shape as 64 decimal JSON bytes.
const (
	rfc8032Seed = "9d61b19deffd5a60ba844af492ec2cc4" +
		"4449c5697b326919703bac031cae7f60"
	rfc8032Public = "d75a980182b10ab7d54bfed3c964073a" +
		"0ee172f3daa62325af021a68f707511a"
)

func solanaVectorJSON(t *testing.T) []byte {
	t.Helper()
	raw, err := hex.DecodeString(rfc8032Seed + rfc8032Public)
	if err != nil {
		t.Fatal(err)
	}
	values := make([]int, len(raw))
	for i, b := range raw {
		values[i] = int(b)
	}
	out, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestFindSolanaKeypairsRFC8032(t *testing.T) {
	keypair := solanaVectorJSON(t)
	data := append([]byte("prefix "), keypair...)
	data = append(data, []byte(" suffix")...)
	matches := findSolanaKeypairs(data, 1000)
	if len(matches) != 1 {
		t.Fatalf("got %d matches, want 1", len(matches))
	}
	if matches[0].startAbs != 1007 || matches[0].endAbs != 1007+int64(len(keypair)) {
		t.Fatalf("match = %+v, want [%d,%d)", matches[0], 1007, 1007+len(keypair))
	}
}

func TestFindSolanaKeypairsRejectsLookalikes(t *testing.T) {
	keypair := solanaVectorJSON(t)
	var values []int
	if err := json.Unmarshal(keypair, &values); err != nil {
		t.Fatal(err)
	}
	values[63] ^= 1 // public half no longer belongs to the seed
	badPublic, _ := json.Marshal(values)

	cases := map[string][]byte{
		"wrong-public-key": badPublic,
		"too-short":        []byte("[1,2,3]"),
		"out-of-range":     []byte("[" + strings.Repeat("256,", 63) + "256]"),
		"ordinary-json":    []byte(`{"numbers":[1,2,3],"name":"wallet"}`),
		"truncated":        keypair[:len(keypair)-1],
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if got := findSolanaKeypairs(input, 0); len(got) != 0 {
				t.Fatalf("lookalike produced matches: %+v", got)
			}
		})
	}
}

func TestScanFindsSolanaKeypairWithoutLeakingIt(t *testing.T) {
	keypair := solanaVectorJSON(t)
	// Place the key across the raw scanner's 4 KiB boundary. The overlap must
	// make it one exactly-once detection rather than a miss or duplicate.
	data := append([]byte(strings.Repeat("x", blockSize-40)), keypair...)
	path := filepath.Join(t.TempDir(), "solana-keypair.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	var dets []Detection
	if err := ScanWithOptions(0, path, Options{}, func(d Detection) {
		dets = append(dets, d)
	}, nil); err != nil {
		t.Fatal(err)
	}
	var matches []Detection
	for _, d := range dets {
		if d.Needle == "solana-keypair" {
			matches = append(matches, d)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("got %d Solana detections in %+v, want 1", len(matches), dets)
	}
	d := matches[0]
	if d.Offset != blockSize-40 || d.MatchLen != len(keypair) {
		t.Fatalf("detection = %+v, want offset %d len %d", d, blockSize-40, len(keypair))
	}
	if strings.Contains(d.Description, string(keypair)) || len(d.Words) != 0 {
		t.Fatalf("detection leaked key material: %+v", d)
	}
}
