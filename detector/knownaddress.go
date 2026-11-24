package detector

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// CanonicalKnownAddress validates one public address shape supported by the
// offline recovery matcher and returns its comparison form. EVM hex and Bech32
// are case-insensitive after syntactic validation; Base58 addresses remain
// case-sensitive. No network lookup is performed.
func CanonicalKnownAddress(address string) (string, error) {
	s := strings.TrimSpace(address)
	if s == "" {
		return "", errors.New("empty address")
	}
	if len(s) > 128 {
		return "", fmt.Errorf("address is %d bytes, maximum is 128", len(s))
	}
	if len(s) == 42 && strings.HasPrefix(strings.ToLower(s), "0x") {
		raw, err := hex.DecodeString(s[2:])
		if err != nil {
			return "", errors.New("malformed EVM address")
		}
		body := s[2:]
		hasLower, hasUpper := false, false
		for i := 0; i < len(body); i++ {
			if body[i] >= 'a' && body[i] <= 'f' {
				hasLower = true
			} else if body[i] >= 'A' && body[i] <= 'F' {
				hasUpper = true
			}
		}
		if hasLower && hasUpper && body != eip55Address(raw)[2:] {
			return "", errors.New("mixed-case EVM address has an invalid EIP-55 checksum")
		}
		return strings.ToLower(s), nil
	}
	if strings.ContainsRune(s, '1') {
		if canonical, ok := canonicalBech32(s); ok {
			return canonical, nil
		}
	}
	if payload, ok := base58CheckDecode(s); ok && len(payload) == 21 {
		return s, nil
	}
	if raw, ok := base58Decode(s); ok && len(raw) == 32 {
		return s, nil
	}
	return "", errors.New("not a supported EVM, Bech32, Base58Check, or 32-byte Base58 address")
}

func canonicalBech32(s string) (string, bool) {
	if len(s) < 8 || len(s) > 90 {
		return "", false
	}
	hasLower, hasUpper := false, false
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] >= 'a' && s[i] <= 'z':
			hasLower = true
		case s[i] >= 'A' && s[i] <= 'Z':
			hasUpper = true
		}
	}
	if hasLower && hasUpper {
		return "", false
	}
	lower := strings.ToLower(s)
	sep := strings.LastIndexByte(lower, '1')
	if sep < 1 || sep+7 > len(lower) {
		return "", false
	}
	hrp := lower[:sep]
	for i := 0; i < len(hrp); i++ {
		if hrp[i] < 33 || hrp[i] > 126 {
			return "", false
		}
	}
	values := make([]int, 0, len(lower)-sep-1)
	for i := sep + 1; i < len(lower); i++ {
		v := strings.IndexByte(bech32Charset, lower[i])
		if v < 0 {
			return "", false
		}
		values = append(values, v)
	}
	if bech32Polymod(append(bech32HRPExpand(hrp), values...)) != 1 {
		return "", false
	}
	return lower, true
}
