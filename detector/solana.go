package detector

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
)

// Solana CLI keypair files are JSON arrays containing the 64-byte Ed25519
// private key (32-byte seed followed by the 32-byte public key). A bare array
// shape is far too common to report on its own, so candidates are accepted
// only when the public half is exactly the key derived from the seed half.
// The key bytes never leave this matcher; detections expose only a label and
// byte range, following the scanner's existing secret-handling contract.

// solanaKeypairMaxSpan bounds JSON decoding and keeps a complete candidate in
// the scanner's overlap window. A normally formatted keypair is under 256
// bytes; 1 KiB leaves ample room for whitespace without admitting unbounded
// JSON input.
const solanaKeypairMaxSpan = 1024

type solanaKeypairMatch struct {
	startAbs int64
	endAbs   int64
}

// findSolanaKeypairs returns cryptographically self-consistent Solana CLI
// keypair arrays fully contained in data. Objects cut at a block edge fail to
// decode here and are retried whole through the scanner overlap.
func findSolanaKeypairs(data []byte, baseAbs int64) []solanaKeypairMatch {
	var matches []solanaKeypairMatch
	for start := 0; start < len(data); {
		rel := bytes.IndexByte(data[start:], '[')
		if rel < 0 {
			break
		}
		candidateStart := start + rel
		endLimit := candidateStart + solanaKeypairMaxSpan
		if endLimit > len(data) {
			endLimit = len(data)
		}

		dec := json.NewDecoder(bytes.NewReader(data[candidateStart:endLimit]))
		var values []int
		if err := dec.Decode(&values); err == nil && validSolanaKeypair(values) {
			end := candidateStart + int(dec.InputOffset())
			matches = append(matches, solanaKeypairMatch{
				startAbs: baseAbs + int64(candidateStart),
				endAbs:   baseAbs + int64(end),
			})
			start = end
			continue
		}
		start = candidateStart + 1
	}
	return matches
}

func validSolanaKeypair(values []int) bool {
	if len(values) != ed25519.PrivateKeySize {
		return false
	}
	privateKey := make([]byte, ed25519.PrivateKeySize)
	for i, value := range values {
		if value < 0 || value > 255 {
			return false
		}
		privateKey[i] = byte(value)
	}
	derived := ed25519.NewKeyFromSeed(privateKey[:ed25519.SeedSize])
	return bytes.Equal(derived[ed25519.SeedSize:], privateKey[ed25519.SeedSize:])
}
